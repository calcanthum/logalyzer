#!/usr/bin/env python3
"""
logalyzer.py — Terminal log analyzer with mouse support
Requires: urwid  →  pip install urwid

Usage:    python logalyzer.py -f <logfile>
          python logalyzer.py -d

Keys:
  /         focus filter bar
  Enter     return to log view
  Esc       clear filter + level pills + field filters, return to log view
  t         toggle live tail
  s         toggle stats panel
  e         export current stats
  d         open Docker container selector
  g / G     jump to top / bottom
  q         quit

Mouse:    scroll wheel navigates the log; click level pills to filter
          click a field value in a log line to start a field filter (two-click confirm)
          left click on a field pill to remove that filter
          right click on a field pill to invert that filter

Log type definitions live in ./logtypes/*.json — copy and edit to add custom types.
"""

import urwid
import re
import os
import sys
import time
import socket as _socket
import http.client
import queue as _queue
import threading
import argparse
import json
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

# Palette
PALETTE = [
    # chrome
    ('header',   'white,bold',        'dark blue'),
    ('h_dim',    'light blue',        'dark blue'),
    ('tail_on',  'light green,bold',  'dark blue'),
    ('tail_off', 'dark gray',         'dark blue'),
    ('footer',   'black',             'light gray'),
    ('fk',       'dark blue,bold',    'light gray'),
    # filter bar
    ('fl',       'dark cyan,bold',    'default'),
    ('fe',       'white',             'dark gray'),
    ('fe_f',     'white,bold',        'dark blue'),
    ('fc',       'light gray',        'default'),
    ('fc_f',     'black',             'light gray'),
    ('ferr',     'light red,bold',    'dark gray'),
    # selector overlay
    ('sel_box',  'white',             'dark blue'),
    # stats bar base
    ('st',       'light gray',        'dark gray'),
    # stats pills — normal
    ('st_e',     'light red',         'dark gray'),
    ('st_w',     'yellow',            'dark gray'),
    ('st_i',     'light green',       'dark gray'),
    ('st_d',     'dark cyan',         'dark gray'),
    # stats pills — active / toggled on
    ('pill_e',   'dark gray,bold',    'light red'),
    ('pill_w',   'dark gray,bold',    'yellow'),
    ('pill_i',   'dark gray,bold',    'light green'),
    ('pill_d',   'white,bold',        'dark cyan'),
    # stats pills — inverted / blacklist mode (coloured text on dark bg)
    ('pill_e_i', 'light red,bold',    'dark gray'),
    ('pill_w_i', 'yellow,bold',       'dark gray'),
    ('pill_i_i', 'light green,bold',  'dark gray'),
    ('pill_d_i', 'dark cyan,bold',    'dark gray'),
    # log line base colours
    ('ln',       'light gray',        'default'),
    ('le',       'light red',         'default'),
    ('lw',       'yellow',            'default'),
    ('li',       'light green',       'default'),
    ('ld',       'dark cyan',         'default'),
    # inline highlights (usable in logtype JSON)
    ('he',       'light red,bold',    'default'),
    ('hw',       'yellow,bold',       'default'),
    ('hi',       'light green,bold',  'default'),
    ('hd',       'dark cyan,bold',    'default'),
    ('hip',      'light cyan',        'default'),
    ('h2ok',     'light green',       'default'),
    ('h3xx',     'yellow',            'default'),
    ('h4xx',     'light red',         'default'),
    ('hm',       'black',             'yellow'),
    ('hsel',     'black,bold',        'dark cyan'),   # pending click selection
    ('lno',      'dark gray',         'default'),
    # scrollbar
    ('scrollbar_thumb', 'dark cyan',   'default'),
    ('scrollbar_trough','dark gray',   'default'),
    # stats pane
    ('sp_border', 'dark cyan',          'default'),
    ('sp_hdr',    'black,bold',         'dark cyan'),
    ('sp_div',    'dark cyan',          'default'),
    ('sp_body',   'light gray',         'default'),
    ('sp_err',    'light red',          'default'),
    ('sp_dim',    'dark gray',          'default'),
    # field filter pills
    ('fpill_n',  'dark cyan',           'dark gray'),   # normal
    ('fpill_a',  'black,bold',          'dark cyan'),   # active / pending
    ('fpill_inv','light red',           'dark gray'),   # inverted (exclusion) pill
    # docker selector
    ('dk_box',   'white',               'dark blue'),
    ('dk_hdr',   'black,bold',          'dark cyan'),
    ('dk_body',  'light gray',          'default'),
    ('dk_err',   'light red,bold',      'default'),
    ('dk_dim',   'dark gray',           'default'),
    ('dk_spin',  'light cyan,bold',     'dark blue'),
]

_BASE_ATTR  = {'error': 'le', 'warn': 'lw', 'info': 'li', 'debug': 'ld'}
_BASE_ATTRS = frozenset({'ln', 'le', 'lw', 'li', 'ld'})


# Log Type System
LOGTYPE_DIR    = Path(__file__).parent / 'logtypes'
DOCKER_SOCKET  = '/var/run/docker.sock'
DOCKER_MAX_LINES = 100_000   # rolling cap on streamed container log lines

# Stats helpers
_MON = {m: i+1 for i, m in enumerate(
    'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split())}

_TS_PATTERNS = [
    # ISO 8601 / nginx error: YYYY-MM-DD or YYYY/MM/DD
    re.compile(r'(\d{4})[-/](\d{2})[-/](\d{2})[T ](\d{2}):(\d{2}):(\d{2})'),
    # nginx/apache combined: [DD/Mon/YYYY:HH:MM:SS  OR  bare DD/Mon/YYYY:HH:MM:SS
    re.compile(r'\[?(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})'),
    # syslog: Jun  1 00:30:45
    re.compile(r'\b(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b'),
    # wine: leading float seconds (no calendar; treat as relative seconds)
    re.compile(r'^(\d+)\.(\d+)'),
]
_RE_IP_STAT    = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

_RE_NGINX_ERR_CLIENT  = re.compile(r',\s*client:\s*(\S+?)(?:,|$)')
_RE_NGINX_ERR_REQUEST = re.compile(r',\s*request:\s*"([A-Z]+) ([^\s"]+)')

_RE_REQUEST    = re.compile(r'^(?P<method>\S+) (?P<path>[^?\s]+)(?P<qs>\S*)')
_RE_PATH_ID    = re.compile(r'/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27})(?=/|$)', re.I)


def _normalize_path(path: str) -> str:
    # Replace numeric IDs and UUIDs in URL paths with {id}.
    return _RE_PATH_ID.sub('/{id}', path)

def _parse_ts(raw: str, strptime_fmt: str | None = None):
    # Parse a pre-extracted timestamp string into a datetime or float.
    if strptime_fmt:
        try:
            return datetime.strptime(raw, strptime_fmt).replace(tzinfo=None)
        except ValueError:
            pass          # fall through to heuristics
    return _extract_ts(raw)

def _extract_ts(line: str):
    # Return a comparable timestamp value (datetime or float) or None.
    m = _TS_PATTERNS[0].search(line)
    if m:
        try: return datetime(int(m[1]),int(m[2]),int(m[3]),int(m[4]),int(m[5]),int(m[6]))
        except ValueError: pass
    m = _TS_PATTERNS[1].search(line)
    if m:
        mon = _MON.get(m[2], 0)
        if mon:
            try: return datetime(int(m[3]),mon,int(m[1]),int(m[4]),int(m[5]),int(m[6]))
            except ValueError: pass
    m = _TS_PATTERNS[2].search(line)
    if m and m[1] in _MON:
        try: return datetime(2000,_MON[m[1]],int(m[2]),int(m[3]),int(m[4]),int(m[5]))
        except ValueError: pass
    m = _TS_PATTERNS[3].match(line)
    if m:
        return float(f'{m[1]}.{m[2]}')
    return None


def _bucket_key(ts, span_secs: float) -> str:
    # Convert a timestamp to a bucket label given total span in seconds.
    if isinstance(ts, datetime):
        if span_secs <= 3600:          # ≤1 h  → per minute
            return ts.strftime('%H:%M')
        elif span_secs <= 86400:       # ≤1 day → per hour
            return ts.strftime('%d %H:00')
        else:
            return ts.strftime('%m-%d')
    else:  # float (wine)
        if span_secs <= 60:
            return f'{int(ts):4d}s'
        return f'{int(ts)//60:3d}m'


def compute_stats(store: 'LineStore', indices: list,
                  log_type=None, n_top: int = 8):
    # Return histogram and top-N panel data for the matched lines, driven by log_type field definitions.
    fields       = getattr(log_type, 'stat_fields', [])
    field_by_type = {f.type: f for f in fields}

    timestamps: list = []
    # Ordered dict preserves JSON declaration order for panel rendering
    text_counters:    dict[str, Counter] = {}
    numeric_counters: dict[str, Counter] = {}

    for f in fields:
        if f.dtype in ('text', 'compound'):
            text_counters[f.type] = Counter()
        elif f.dtype == 'numeric':
            numeric_counters[f.type] = Counter()

    for i in indices:
        line, lvl = store[i]

        for f in fields:

            if f.dtype == 'timestamp':
                raw = f.extract(line)
                if raw:
                    ts = _parse_ts(raw, f.strptime)
                    if ts is not None:
                        timestamps.append(ts)

            elif f.dtype == 'text':
                if f.error_levels and lvl not in f.error_levels:
                    continue
                if f.multi:
                    for val in (f.extract(line) or []):
                        if val:
                            text_counters[f.type][val.strip()[:80]] += 1
                else:
                    val = f.extract(line)
                    if val:
                        text_counters[f.type][val.strip()[:80]] += 1

            elif f.dtype == 'numeric':
                val = f.extract(line)
                if val:
                    try:
                        n = int(val)
                        if f.buckets:
                            for b in f.buckets:
                                lo, hi = b['range']
                                if lo <= n <= hi:
                                    numeric_counters[f.type][b['label']] += 1
                                    break
                        else:
                            numeric_counters[f.type][str(n)] += 1
                    except ValueError:
                        pass

            elif f.dtype == 'compound':
                parts = {}
                for comp_type in f.components:
                    cf = field_by_type.get(comp_type)
                    if cf:
                        v = cf.extract(line)
                        if v:
                            if cf.normalize:
                                v = _normalize_path(v)
                            parts[comp_type] = v
                if len(parts) == len(f.components):
                    try:
                        key = f.format.format(**parts)[:80]
                        text_counters[f.type][key] += 1
                    except KeyError:
                        pass

    # Histogram
    histogram = []
    if timestamps:
        if all(isinstance(t, datetime) for t in timestamps):
            span = (max(timestamps) - min(timestamps)).total_seconds()
            buckets: Counter = Counter(_bucket_key(t, span) for t in timestamps)
            histogram = sorted(buckets.items())
        elif all(isinstance(t, float) for t in timestamps):
            span = max(timestamps) - min(timestamps)
            buckets = Counter(_bucket_key(t, span) for t in timestamps)
            histogram = sorted(buckets.items(), key=lambda x: x[0])

    # Ordered panels (preserves JSON field declaration order)
    panels = []
    for f in fields:
        if f.dtype == 'timestamp':
            continue
        elif f.dtype in ('text', 'compound'):
            entries = text_counters[f.type].most_common(n_top)
            if entries:
                panels.append((f.label, 'text', entries))
        elif f.dtype == 'numeric':
            entries = numeric_counters[f.type].most_common(n_top)
            if entries:
                panels.append((f.label, 'numeric', entries))

    return {
        'histogram': histogram,
        'panels':    panels,
    }



def _hl(tokens: list, pattern: re.Pattern, attr: str, base_only: bool = True) -> list:
    # Single syntax-highlight pass over a [(attr, text), ...] token list.
    out = []
    for a, text in tokens:
        if base_only and a not in _BASE_ATTRS:
            out.append((a, text))
            continue
        pos = 0
        for m in pattern.finditer(text):
            if m.start() > pos:
                out.append((a, text[pos:m.start()]))
            out.append((attr, m.group(0)))
            pos = m.end()
        if pos < len(text):
            out.append((a, text[pos:]))
    return [(a, t) for a, t in out if t]


def _hl_span(tokens: list, start: int, end: int, attr: str) -> list:
    # Overlay a highlight over character range [start, end) in a token list.
    out = []
    pos = 0
    for a, text in tokens:
        tstart = pos
        tend   = pos + len(text)
        if tend <= start or tstart >= end:
            out.append((a, text))
        else:
            if tstart < start:
                out.append((a, text[:start - tstart]))
            hl_s = max(0, start - tstart)
            hl_e = min(len(text), end - tstart)
            if hl_s < hl_e:
                out.append((attr, text[hl_s:hl_e]))
            if tend > end:
                out.append((a, text[end - tstart:]))
        pos = tend
    return [(a, t) for a, t in out if t]


class HighlightRule:
    def __init__(self, d: dict):
        flags          = re.IGNORECASE if 'i' in d.get('flags', '') else 0
        self.re        = re.compile(d['regex'], flags)
        self.attr      = d['attr']
        self.base_only = d.get('base_only', True)


class LevelRule:
    def __init__(self, d: dict):
        flags      = re.IGNORECASE if 'i' in d.get('flags', '') else 0
        self.re    = re.compile(d['regex'], flags)
        self.level = d['level']


class StatField:
    # A named semantic field used by compute_stats for extraction.
    def __init__(self, d: dict):
        self.type         = d['type']
        self.label        = d.get('label', self.type.replace('_', ' ').title())
        self.dtype        = d.get('dtype', 'text')
        flags             = re.IGNORECASE if 'i' in d.get('flags', '') else 0
        self.re           = re.compile(d['regex'], flags) if 'regex' in d else None
        self.group        = d.get('group', 1)
        self.multi        = d.get('multi', False)
        self.normalize    = d.get('normalize', False)
        self.error_levels = set(d.get('error_levels', []))
        # numeric: list of {"range": [lo, hi], "label": "..."} bucket specs
        self.buckets      = d.get('buckets', [])
        # compound: list of sibling field type names to join
        self.components   = d.get('components', [])
        # compound: python str.format template, keys are component type names
        self.format       = d.get('format', '')
        # filterable: if True, clicking on the matched span in the log view
        # will offer to filter on this field's value (two-click confirm flow)
        self.filterable   = d.get('filterable', False)
        self.strptime     = d.get('strptime', None)

    def extract(self, line: str):
        if self.multi:
            return self.re.findall(line) if self.re else []
        result = self.extract_with_span(line)
        return result[0] if result else None

    def extract_with_span(self, line: str):
        """Return (value, start, end) of the captured group, or None.
        Used for click hit-testing; not supported for multi fields."""
        if self.re is None or self.multi:
            return None
        m = self.re.search(line)
        if not m:
            return None
        try:
            val = m.group(self.group)
            if val:
                return val, m.start(self.group), m.end(self.group)
        except IndexError:
            pass
        return None


class LogType:
    def __init__(self, d: dict):
        self.id   = d['id']
        self.name = d['name']

        det         = d.get('detect', {})
        self._kw    = [k.lower() for k in det.get('filename_keywords', [])]
        cp          = det.get('content_regex', '')
        self._cre   = re.compile(cp) if cp else None

        self.level_rules     = [LevelRule(r)     for r in d.get('level_rules', [])]
        self.highlight_rules = [HighlightRule(r) for r in d.get('highlights', [])]
        # Optional per-type pill labels e.g. {"error": "5xx", "warn": "4xx", ...}
        self.level_labels: dict = d.get('level_labels', {})
        # Pre-compiled combined level regex: one pass instead of N per line
        self._combined_re, self._combined_map = self._build_combined_re()
        # Semantic field extractors used by compute_stats
        self.stat_fields: list = [StatField(f) for f in d.get('fields', [])]

    def _build_combined_re(self):
        if not self.level_rules:
            return None, {}
        """
        Build a flat alternation where word-boundary assertions sit OUTSIDE
        named groups so the engine can short-circuit without entering the group.
        (FOO|BAR)  ->  (?P<g>FOO|BAR)
        Other patterns wrapped as-is: (?P<g>pattern)
        """
        _strip_wb = re.compile(r'^((?:\\b)*)(.+?)((?:\\b)*)$', re.DOTALL)
        parts   = []
        grp_map = {}
        for i, rule in enumerate(self.level_rules):
            grp = f'_lvl{i}'
            pat = rule.re.pattern
            # hoist leading/trailing \b outside named group
            m   = re.match(r'^((?:\\b)+)?(.+?)((?:\\b)+)?$', pat, re.DOTALL)
            if m:
                pre  = m.group(1) or ''
                body = m.group(2)
                suf  = m.group(3) or ''
                # strip outer capture group from body if present: (X) -> X
                inner = re.sub(r'^\(([^()]+)\)$', r'\1', body)
                parts.append(f'{pre}(?P<{grp}>{inner}){suf}')
            else:
                parts.append(f'(?P<{grp}>{pat})')
            grp_map[grp] = rule.level
        flags = re.IGNORECASE if any(
            re.IGNORECASE & r.re.flags for r in self.level_rules) else 0
        try:
            return re.compile('|'.join(parts), flags), grp_map
        except re.error:
            parts2 = [f'(?P<_lvl{i}>{r.re.pattern})' 
                    for i, r in enumerate(self.level_rules)]
            try:
                return re.compile('|'.join(parts2), flags), grp_map
            except re.error as exc:
                print(
                    f'[logalyzer warn] log type {self.id!r}: '
                    f'could not build combined level regex, falling back to individual rules. '
                    f'Reason: {exc}',
                    file=sys.stderr,
                )
                return None, {}

    def score(self, path: str, lines: list) -> int:
        # Heuristic match score against a file path + content sample.
        s    = 0
        name = os.path.basename(path).lower()
        for kw in self._kw:
            if kw in name:
                s += 10
        if self._cre:
            for line in lines[:20]:
                if self._cre.search(line):
                    s += 5
                    break
        return s

    def detect_level(self, line: str) -> str:
        if self._combined_re is None:
            # Fallback: individual rule pass
            for rule in self.level_rules:
                if rule.re.search(line):
                    return rule.level
            return 'normal'
        m = self._combined_re.search(line)
        if m:
            return self._combined_map.get(m.lastgroup, 'normal')
        return 'normal'

    def make_markup(self, line: str, level: str,
                    search_re=None, lineno: int = None) -> list:
        base = _BASE_ATTR.get(level, 'ln')
        toks = [(base, line)]
        for rule in self.highlight_rules:
            toks = _hl(toks, rule.re, rule.attr, rule.base_only)
        if search_re:
            # search match overrides everything — base_only=False
            toks = _hl(toks, search_re, 'hm', base_only=False)
        pfx  = [('lno', f'{lineno:6d} \u2502 ')] if lineno is not None else []
        return pfx + toks


def load_log_types() -> list:
    types = []
    for fp in sorted(LOGTYPE_DIR.glob('*.json')):
        try:
            with open(fp) as f:
                data = json.load(f)
            if 'id' in data and 'name' in data:
                types.append(LogType(data))
        except Exception as e:
            print(f'[logalyzer warn] {fp.name}: {e}', file=sys.stderr)
    if not types:
        types.append(LogType({
            'id': 'other', 'name': 'Plain / Other (no highlighting)',
            'detect': {}, 'level_rules': [], 'highlights': [],
        }))
    return types


def auto_detect(path: str, lines: list, log_types: list) -> LogType:
    return max(log_types, key=lambda lt: lt.score(path, lines))


# Log Data

class LineStore:
    # All mutations go through here. Enforces len(lines) == len(levels)

    def __init__(self, log_type: 'LogType'):
        self._lines:  list = []
        self._levels: list = []
        self._lt           = log_type

    # Size / access

    def __len__(self) -> int:
        return len(self._lines)

    def __getitem__(self, idx: int):
        # Return (line_text, level) for a given index.
        return self._lines[idx], self._levels[idx]

    def get_line(self, idx: int) -> str:
        return self._lines[idx]

    def get_level(self, idx: int) -> str:
        return self._levels[idx]

    # Mutation

    def append(self, line: str) -> None:
        # Append a line and automatically classify its level.
        self._lines.append(line)
        self._levels.append(self._lt.detect_level(line))

    def bulk_load(self, lines: list, levels: list) -> None:
        # Replace all content in one atomic operation (used by async loader).
        assert len(lines) == len(levels), (
            f'bulk_load: lines/levels length mismatch ({len(lines)} vs {len(levels)})')
        self._lines  = lines
        self._levels = levels

    def replace_levels(self, new_levels: list) -> None:
        # Replace level classifications after an async reclassification pass.
        assert len(new_levels) == len(self._lines), (
            f'replace_levels: length mismatch ({len(new_levels)} vs {len(self._lines)})')
        self._levels = new_levels

    def set_log_type(self, lt: 'LogType') -> None:
        # Switch log type and reclassify all existing lines synchronously.
        self._lt     = lt
        self._levels = [lt.detect_level(l) for l in self._lines]

    def trim_front(self, n: int) -> None:
        # Remove the first *n* entries (used for the Docker rolling cap).
        self._lines  = self._lines[n:]
        self._levels = self._levels[n:]

    # Queries

    def level_counts(self, indices=None) -> dict:
        src = self._levels if indices is None else [self._levels[i] for i in indices]
        c: dict = defaultdict(int)
        for lv in src:
            c[lv] += 1
        return dict(c)

    @property
    def log_type(self) -> 'LogType':
        return self._lt


class LogData:
    def __init__(self, path: str, log_type: LogType, display_name: str = ''):
        self.path         = path
        self.display_name = display_name or os.path.basename(path)
        self.log_type     = log_type
        self.store        = LineStore(log_type)
        self._file_pos    = 0

    def set_type(self, lt: LogType) -> None:
        # Switch log type and reclassify all stored lines (synchronous).
        self.log_type = lt
        self.store.set_log_type(lt)

    def load(self) -> None:
        with open(self.path, errors='replace') as fh:
            raw = fh.readlines()
        lines  = [l.rstrip('\n') for l in raw]
        levels = [self.log_type.detect_level(l) for l in lines]
        self.store.bulk_load(lines, levels)
        self._file_pos = os.path.getsize(self.path)

    def load_async(self, progress_cb=None, done_cb=None) -> None:
        """
        Load in a background thread. Calls progress_cb(byte_pos) periodically
        and done_cb() when complete. Both callbacks are invoked from the worker
        thread. Callers must ensure thread-safety (e.g. via urwid pipe).
        """
        import threading

        def _worker():
            CHUNK  = 4 * 1024 * 1024   # 4 MB read chunks
            lines  = []
            levels = []
            lt     = self.log_type
            try:
                with open(self.path, errors='replace') as fh:
                    buf = fh.buffer   # underlying binary stream for tell()
                    while True:
                        chunk = fh.readlines(CHUNK)
                        if not chunk:
                            break
                        stripped = [l.rstrip('\n') for l in chunk]
                        lvls     = [lt.detect_level(l) for l in stripped]
                        lines.extend(stripped)
                        levels.extend(lvls)
                        if progress_cb:
                            progress_cb(buf.tell())   # actual byte position
                self.store.bulk_load(lines, levels)
                self._file_pos = os.path.getsize(self.path)
            except Exception as e:
                self.store.bulk_load([f'[load error] {e}'], ['error'])
            if done_cb:
                done_cb()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def poll_new(self) -> list:
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []
        if size <= self._file_pos:
            return []
        new = []
        with open(self.path, errors='replace') as fh:
            fh.seek(self._file_pos)
            for raw in fh:
                l = raw.rstrip('\n')
                new.append(l)
                self.store.append(l)   # classifies and appends atomically
        self._file_pos = size
        return new

    def level_counts(self, indices=None) -> dict:
        return self.store.level_counts(indices)




# Lazy List Walker
class LazyListWalker(urwid.ListWalker):
    """
    ListWalker that defers make_markup to render time.
    Holds a list of (line_index, ...) references; builds urwid. Text widgets
    only for the rows the ListBox is about to paint (~screen height rows).
    An LRU cache bounds memory; invalidated on filter/type change.
    """
    CACHE_SIZE = 600   # ~20 screenfuls at 30 rows each

    def __init__(self):
        self._store    = None          # LineStore reference set by reset()
        self._lt       = None
        self._lno      = True
        self._fre      = None
        self._indices  = []        # list of raw line indices to display
        self._focus    = 0
        self._cache: dict = {}
        self._cache_order: list = []
        self._pending_raw:  int | None   = None   # raw line index with pending selection
        self._pending_span: tuple | None = None   # (col_start, col_end) in raw line chars

    # Public setters
    def reset(self, store, lt, lno, fre, indices):
        self._store   = store
        self._lt      = lt
        self._lno     = lno
        self._fre     = fre
        self._indices = indices
        self._focus   = max(0, min(self._focus, len(indices) - 1))
        self._cache.clear()
        self._cache_order.clear()
        self._modified()

    def set_focus(self, pos):
        if 0 <= pos < len(self._indices):
            self._focus = pos
            self._modified()

    def set_pending(self, raw_line_idx: int, col_start: int, col_end: int) -> None:
        # Highlight a span on one raw line as a pending click-selection.
        self._pending_raw  = raw_line_idx
        self._pending_span = (col_start, col_end)
        self._evict_raw(raw_line_idx)
        self._modified()

    def clear_pending(self) -> None:
        # Remove any pending selection highlight.
        if self._pending_raw is None:
            return
        old = self._pending_raw
        self._pending_raw  = None
        self._pending_span = None
        self._evict_raw(old)
        self._modified()

    def _evict_raw(self, raw_line_idx: int) -> None:
        # Evict all cache entries whose raw index matches raw_line_idx.
        evict = [p for p, ridx in
                 ((p, self._indices[p]) for p in list(self._cache))
                 if ridx == raw_line_idx]
        for p in evict:
            self._cache.pop(p, None)
            try: self._cache_order.remove(p)
            except ValueError: pass

    # Cache
    def _build(self, pos):
        if pos in self._cache:
            return self._cache[pos]
        i          = self._indices[pos]
        line, lvl  = self._store[i]
        mu  = self._lt.make_markup(
            line, lvl,
            self._fre, i + 1 if self._lno else None)
        # Overlay pending selection highlight on the matched character span
        if self._pending_raw == i and self._pending_span:
            lno_w = len(f'{i + 1:6d} \u2502 ') if self._lno else 0
            cs, ce = self._pending_span
            mu = _hl_span(mu, lno_w + cs, lno_w + ce, 'hsel')
        w   = urwid.Text(mu, wrap='clip')
        if len(self._cache) >= self.CACHE_SIZE:
            evict = self._cache_order.pop(0)
            self._cache.pop(evict, None)
        self._cache[pos] = w
        self._cache_order.append(pos)
        return w

    # ListWalker protocol
    def __len__(self):
        return len(self._indices)

    def get_focus(self):
        if not self._indices:
            return None, None
        return self._build(self._focus), self._focus

    def get_next(self, pos):
        nxt = pos + 1
        if nxt >= len(self._indices):
            return None, None
        return self._build(nxt), nxt

    def get_prev(self, pos):
        prv = pos - 1
        if prv < 0:
            return None, None
        return self._build(prv), prv

    # Scrolling protocol (for ScrollBar)
    def get_scrollpos(self, size=None, focus=False):
        return self._focus

    def rows_max(self, size=None, focus=False):
        return len(self._indices)


# ScrollBar
class ClickScrollBar(urwid.ScrollBar):

    def mouse_event(self, size, event, button, col, row, focus):
        maxcol  = size[0]
        sb_col  = maxcol - self.scrollbar_width
        on_sb   = col >= sb_col
        ow      = self._original_widget
        ow_size = self._original_widget_size or (sb_col, size[1])

        # Not on the scrollbar strip, including wheel. Delegate to ListBox
        if not on_sb:
            return super().mouse_event(size, event, button, col, row, focus)

        # Scroll wheel on the scrollbar strip
        if button == 4:
            for _ in range(3): ow.keypress(ow_size, 'up')
            return True
        if button == 5:
            for _ in range(3): ow.keypress(ow_size, 'down')
            return True

        # Left-click to jump to position
        if button == 1 and event == 'mouse press':
            maxrow   = size[1]
            rows_max = ow.rows_max(ow_size, focus=True)
            if rows_max > maxrow:
                posmax = rows_max - maxrow
                target = round(max(0.0, min(1.0, row / max(1, maxrow - 1))) * posmax)
                ow.focus_position = max(0, min(len(ow.body) - 1, target))
            return True

        return False


# Widgets
class FilterEdit(urwid.Edit):
    # Edit that lets Enter/Esc bubble up to unhandled_input.
    def keypress(self, size, key):
        if key in ('enter', 'esc'):
            return key
        return super().keypress(size, key)


class BasePill(urwid.WidgetWrap):
    """
    Shared base for pill widgets (LevelPill, FieldPill).
    Owns: SelectableIcon/AttrMap construction, selectable(), mouse routing.
    Subclasses implement: _redraw(), _on_left(), _on_right().
    """

    def __init__(self, initial_attr: str, focus_attr: str | None = None):
        self._icon = urwid.SelectableIcon('', 0)
        self._am   = urwid.AttrMap(self._icon, initial_attr, focus_attr)
        super().__init__(self._am)

    def selectable(self):
        return True

    def mouse_event(self, size, event, button, col, row, focus):
        if event == 'mouse press' and button == 1:
            self._on_left()
            return True
        if event == 'mouse press' and button == 3:
            self._on_right()
            return True
        return False

    def _on_left(self):  raise NotImplementedError
    def _on_right(self): raise NotImplementedError
    def _redraw(self):   raise NotImplementedError


class LevelPill(BasePill):
    signals = ['change']

    # (label, normal_attr, whitelist_attr, blacklist_attr)
    _DEFS = {
        'error': ('ERR',  'st_e', 'pill_e', 'pill_e_i'),
        'warn':  ('WARN', 'st_w', 'pill_w', 'pill_w_i'),
        'info':  ('INFO', 'st_i', 'pill_i', 'pill_i_i'),
        'debug': ('DBG',  'st_d', 'pill_d', 'pill_d_i'),
    }

    def __init__(self, level_key: str):
        self.level_key                            = level_key
        self._label, self._na, self._aa, self._ia = self._DEFS[level_key]
        self._count   = 0
        self.active   = False   # True when any filter mode is on
        self.inverted = False   # True when in blacklist (exclusion) mode
        super().__init__(self._na)
        self._redraw()

    def _redraw(self):
        if self.active and self.inverted:
            mark = '\u2260'   # ≠ "not this level"
            attr = self._ia
        elif self.active:
            mark = '\u25b6'   # ▶ "show only this level"
            attr = self._aa
        else:
            mark = ' '
            attr = self._na
        self._icon.set_text(f' {mark}{self._label} {self._count:,} ')
        self._am.set_attr_map({None: attr})

    def update(self, count: int) -> None:
        self._count = count
        self._redraw()

    def relabel(self, label: str) -> None:
        self._label = label
        self._redraw()

    def reset(self) -> None:
        self.active   = False
        self.inverted = False
        self._redraw()

    def keypress(self, size, key):
        if key in ('enter', ' '):
            self._fire(invert=False)
            return
        return key

    def _on_left(self):  self._fire(invert=False)
    def _on_right(self): self._fire(invert=True)

    def _fire(self, invert: bool = False) -> None:
        already_active = self.active and (self.inverted == invert)
        self.active    = not already_active
        self.inverted  = invert if self.active else False
        self._redraw()
        urwid.emit_signal(self, 'change', self, self.active)


class FieldPill(BasePill):
    """
    Removable pill representing an active field filter value.

    Normal   :  ▶ Label:value ×   (fpill_n — cyan)
    Inverted :  ≠ Label:value ×   (fpill_inv — red)  — excludes matching lines

    Left-click  → remove the filter entirely
    Right-click → toggle between normal (include) and inverted (exclude) mode
    """
    signals = ['remove', 'toggle_invert']

    def __init__(self, field_type: str, label: str, value: str,
                 inverted: bool = False):
        self.field_type = field_type
        self.label      = label
        self.value      = value
        self.inverted   = inverted
        super().__init__(self._pill_attr(), 'fpill_a')
        self._redraw()

    def _pill_attr(self) -> str:
        return 'fpill_inv' if self.inverted else 'fpill_n'

    def _redraw(self):
        short_val = self.value[:24]
        prefix    = '\u2260' if self.inverted else '\u25b6'   # ≠ or ▶
        self._icon.set_text(f' {prefix}{self.label}:{short_val} \u00d7 ')
        self._am.set_attr_map({None: self._pill_attr()})

    def keypress(self, size, key):
        if key in ('enter', ' ', 'delete', 'backspace'):
            urwid.emit_signal(self, 'remove', self)
            return
        return key

    def _on_left(self):  urwid.emit_signal(self, 'remove', self)
    def _on_right(self): urwid.emit_signal(self, 'toggle_invert', self)


class ClickableListBox(urwid.ListBox):
    def __init__(self, body, click_cb=None):
        super().__init__(body)
        self._click_cb = click_cb

    def mouse_event(self, size, event, button, col, row, focus):
        if event == 'mouse press' and button == 1 and self._click_cb:
            wpos = self._row_to_wpos(size, row)
            if wpos is not None and self._click_cb(wpos, col):
                return True
        return super().mouse_event(size, event, button, col, row, focus)

    def _row_to_wpos(self, size, target_row):
        try:
            _, focus_pos = self.body.get_focus()
            if focus_pos is None:
                return None
            offset, inset = self.get_focus_offset_inset(size)
            top_pos = focus_pos - offset
            return top_pos + target_row
        except Exception:
            return None


# Stats Pane
STATS_WIDTH = 44   # chars for the right-side pane (including border)
_HBAR_W     = 20   # chars available for histogram bars


def _bar(count: int, max_count: int, width: int = _HBAR_W, chars: str = '█░') -> str:
    if max_count == 0:
        return chars[1] * width   # return all-empty bar, using the right empty char
    filled = round(count / max_count * width)
    return chars[0] * filled + chars[1] * (width - filled)


def build_stats_pane(stats: dict, title_suffix: str = '') -> urwid.Widget:
    # Build a urwid pile from whatever panels compute_stats returns.
    items = []
    first = True

    def _div():
        return urwid.AttrMap(urwid.Divider('─'), 'sp_div')

    def _hdr(text):
        return urwid.AttrMap(urwid.Text(f' {text} ', wrap='clip'), 'sp_hdr')

    def _row(text, attr='sp_body'):
        return urwid.AttrMap(urwid.Text(text, wrap='clip'), attr)

    def _section(header, rows):
        nonlocal first
        if not rows:
            return
        if not first:
            items.append(_div())
        first = False
        items.append(_hdr(header))
        items.extend(rows)

    # Activity Histogram (always first)
    hist = stats.get('histogram', [])
    if hist:
        max_v = max(c for _, c in hist)
        rows  = [_row(f' {label:>6} {_bar(count, max_v)} {count:>5}')
                 for label, count in hist]
        _section('Activity', rows)

    # Generic panels in JSON declaration order
    for label, kind, entries in stats.get('panels', []):
        if not entries:
            continue
        max_v = entries[0][1]
        if kind == 'numeric':
            rows = [_row(f' {val:<6} {_bar(count, max_v, width=16)} {count:>5}')
                    for val, count in entries]
        else:
            # two-line layout for long values (endpoints, messages, etc.)
            val_w = STATS_WIDTH - 20
            if any(len(v) > 16 for v, _ in entries):
                rows = []
                for val, count in entries:
                    bar = _bar(count, max_v, width=10)
                    rows.append(_row(f' {bar} {count:>4}'))
                    rows.append(_row(f'  {val[:val_w]}'))
            else:
                rows = [_row(f' {val:<16} {_bar(count, max_v, width=12)} {count:>5}')
                        for val, count in entries]
        _section(label, rows)

    if not items:
        items.append(_row('  (no stats available)', 'sp_dim'))

    walker  = urwid.SimpleListWalker(items)
    listbox = urwid.ListBox(walker)
    lined   = urwid.LineBox(listbox, title=f' Stats{title_suffix} ', lline='│',
                             rline=' ', tline='─', bline='─',
                             tlcorner='┌', trcorner='─',
                             blcorner='└', brcorner='─')
    return urwid.AttrMap(lined, 'sp_border')


# Log Type Selector Overlay
def make_selector_overlay(behind: urwid.Widget,
                           log_types: list,
                           detected: LogType,
                           on_select) -> urwid.Overlay:
    items     = []
    focus_idx = 0
    for i, lt in enumerate(log_types):
        suffix = '  \u25c4 auto-detected' if lt is detected else ''
        btn    = urwid.Button(f' {lt.name}{suffix} ')
        urwid.connect_signal(btn, 'click', lambda _b, l=lt: on_select(l))
        items.append(urwid.AttrMap(btn, 'fc', 'fc_f'))
        if lt is detected:
            focus_idx = i

    items += [
        urwid.Divider('\u2500'),
        urwid.Text([
            ('h_dim', '  \u2191\u2193 '), ('st', 'navigate  '),
            ('fk', 'Enter'), ('st', ' select  '),
            ('fk', 'Esc'),   ('st', ' use auto-detected  '),
        ], align='center'),
    ]

    walker  = urwid.SimpleListWalker(items)
    listbox = urwid.ListBox(walker)
    listbox.focus_position = focus_idx

    box = urwid.AttrMap(
        urwid.LineBox(listbox, title=' \u25c9 LogAlyzer \u2014 Select Log Type '),
        'sel_box',
    )

    height = min(len(log_types) + 5, 22)
    return urwid.Overlay(
        box, behind,
        'center', ('relative', 55),
        'middle', height,
    )


# Docker Integration

class _UnixHTTPConnection(http.client.HTTPConnection):
    # HTTPConnection that dials a Unix domain socket.
    def __init__(self, socket_path: str):
        super().__init__('localhost')
        self._socket_path = socket_path

    def connect(self) -> None:
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.connect(self._socket_path)
        self.sock = s


def docker_available() -> bool:
    return os.path.exists(DOCKER_SOCKET)


def docker_list_containers() -> list:
    """
    Fetch running containers from the Docker Engine API.
    Returns a list of dicts: {id, short_id, name, image, status}.
    Raises OSError / json.JSONDecodeError on failure.
    """
    conn = _UnixHTTPConnection(DOCKER_SOCKET)
    conn.timeout = 5.0
    conn.request('GET', '/containers/json', headers={'Accept': 'application/json'})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    containers = []
    for c in json.loads(body):
        name = (c.get('Names') or [''])[0].lstrip('/')
        containers.append({
            'id':       c['Id'],
            'short_id': c['Id'][:12],
            'name':     name,
            'image':    c.get('Image', ''),
            'status':   c.get('Status', ''),
        })
    return containers


class DockerStreamer:
    """
    Streams container logs from the Docker Unix socket into a caller-supplied SimpleQueue.
    Must be drained exclusively from the urwid main-loop thread.

    Queue message tuples:
      ('line',  str)   -- one log line
      ('error', str)   -- fatal error; thread exits after this
      ('eof',   None)  -- stream closed
    """

    def __init__(self, container_id: str, q: _queue.SimpleQueue,
                 write_fd: int, tail: int = 500):
        self._id     = container_id
        self._q      = q
        self._fd     = write_fd
        self._tail   = tail
        self._stop   = threading.Event()
        self._sock   = None                 # set in _run(); guarded by _stop
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=f'docker-stream-{container_id[:8]}')

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        # Signal the stream thread to exit and unblock any pending recv().
        self._stop.set()
        s = self._sock
        if s is not None:
            try:   s.close()
            except OSError: pass

    # Internal

    def _wake(self) -> None:
        try:   os.write(self._fd, b'x')
        except OSError: pass

    def _put(self, kind: str, payload) -> None:
        self._q.put((kind, payload))
        self._wake()

    def _run(self) -> None:
        # Open socket
        try:
            s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            s.connect(DOCKER_SOCKET)
            self._sock = s
        except OSError as exc:
            self._put('error', f'Cannot connect to Docker socket: {exc}')
            return

        """
        Send HTTP request. HTTP/1.0 disables chunked transfer-encoding so 
        Docker streams raw multiplexed frames with no chunk-size lines interleaved.
        """

        path = (f'/containers/{self._id}/logs'
                f'?follow=1&stdout=1&stderr=1&tail={self._tail}')
        req  = (f'GET {path} HTTP/1.0\r\n'
                f'Host: localhost\r\n\r\n')
        try:
            s.sendall(req.encode())
        except OSError as exc:
            self._put('error', f'Docker log request failed: {exc}')
            return

        # Consume HTTP response headers
        buf = b''
        try:
            while b'\r\n\r\n' not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    self._put('eof', None)
                    return
                buf += chunk
        except OSError as exc:
            if not self._stop.is_set():
                self._put('error', f'Reading HTTP headers: {exc}')
            return

        # Body starts after the blank line; buf may contain some of it
        leftover = buf[buf.index(b'\r\n\r\n') + 4:]

        """
        Docker multiplexed-stream frame loop
        Each frame: [stream_type:1][pad:3][length:4][payload:length]
        stream_type: 1=stdout  2=stderr
        Containers with a TTY skip this framing.
        The first byte of a framed stream is always 1 or 2; a TTY stream
        starts directly with printable ASCII, so we sniff on the first byte.
        """
        tty_mode = False

        def _fill(need: int) -> bool:
            # Grow `leftover` to at least `need` bytes. Returns False on EOF/stop.
            nonlocal leftover
            while len(leftover) < need:
                if self._stop.is_set():
                    return False
                try:
                    chunk = s.recv(max(4096, need - len(leftover)))
                except OSError:
                    return False
                if not chunk:
                    return False
                leftover += chunk
            return True

        # Sniff: wait for at least 1 byte to decide framing mode
        if not _fill(1):
            self._put('eof', None)
            return

        if leftover[0] not in (1, 2):
            tty_mode = True

        while not self._stop.is_set():
            if tty_mode:
                # Raw text stream — split on newlines
                if not _fill(1):
                    break
                newline_pos = leftover.find(b'\n')
                if newline_pos == -1:
                    # No newline yet; grab whatever is there and ask for more
                    if not _fill(len(leftover) + 1):
                        break
                    continue
                line     = leftover[:newline_pos].decode('utf-8', errors='replace')
                leftover = leftover[newline_pos + 1:]
                if line:
                    self._put('line', line)
            else:
                # Multiplexed framing
                if not _fill(8):
                    break
                header  = leftover[:8]
                # stream_type = header[0]  — could distinguish stdout/stderr here
                length  = int.from_bytes(header[4:8], 'big')
                leftover = leftover[8:]
                if length == 0:
                    continue
                if not _fill(length):
                    break
                payload  = leftover[:length]
                leftover = leftover[length:]
                line     = payload.decode('utf-8', errors='replace').rstrip('\n')
                if line:
                    self._put('line', line)

        self._put('eof', None)
        try:   s.close()
        except OSError: pass


# Docker Selector Overlay

def make_docker_selector_overlay(behind: urwid.Widget,
                                  state: str,
                                  containers: list,
                                  error_msg: str,
                                  on_select,
                                  on_cancel) -> urwid.Overlay:
    """
    state:      'loading' | 'ready' | 'error'
    containers: list of dicts from docker_list_containers()
    error_msg:  shown when state == 'error'
    on_select:  callable(container_dict)
    on_cancel:  callable()
    """
    items = []

    if state == 'loading':
        items.append(urwid.AttrMap(
            urwid.Text(' \u25cc  Connecting to Docker\u2026', align='center'),
            'dk_spin'))

    elif state == 'error':
        items.append(urwid.AttrMap(
            urwid.Text(f' \u26a0  {error_msg}', wrap='any'), 'dk_err'))
        items.append(urwid.Divider())
        items.append(urwid.Text(
            [('dk_dim', ' Is the Docker daemon running? '
              'You may need to be in the docker group.')],
            wrap='any'))

    else:  # ready
        if not containers:
            items.append(urwid.AttrMap(
                urwid.Text(' (no running containers found)', align='center'),
                'dk_dim'))
        else:
            items.append(urwid.AttrMap(
                urwid.Text(' Container                      Image', wrap='clip'),
                'dk_hdr'))
            items.append(urwid.Divider('\u2500'))
            for c in containers:
                label = f" {c['name']:<30} {c['image'][:28]}"
                sublabel = f"   {c['short_id']}  {c['status']}"
                btn = urwid.Button(label)
                urwid.connect_signal(btn, 'click', lambda _b, _c=c: on_select(_c))
                items.append(urwid.AttrMap(btn, 'fc', 'fc_f'))
                items.append(urwid.AttrMap(
                    urwid.Text(sublabel, wrap='clip'), 'dk_dim'))

    items += [
        urwid.Divider('\u2500'),
        urwid.Text([
            ('h_dim', '  \u2191\u2193 '), ('st', 'navigate  '),
            ('fk', 'Enter'), ('st', ' select  '),
            ('fk', 'Esc'), ('st', ' cancel  '),
        ], align='center'),
    ]

    walker  = urwid.SimpleListWalker(items)
    listbox = urwid.ListBox(walker)
    # Focus the first button when ready
    if state == 'ready' and containers:
        listbox.focus_position = 2   # skip header + divider

    box = urwid.AttrMap(
        urwid.LineBox(listbox, title=' \u25c9 LogAlyzer \u2014 Docker Containers '),
        'dk_box',
    )

    n_items = len(containers) * 2 + 5 if state == 'ready' else 6
    height  = min(max(n_items, 6), 28)
    return urwid.Overlay(
        box, behind,
        'center', ('relative', 62),
        'middle', height,
    )


# Stats plain-text export
_EXPORT_BAR_W = 24   # width of ASCII progress bar in exported file
_EXPORT_VAL_W = 32   # max chars for a value label column


def export_stats_to_text(stats: dict, data: 'LogData', log_type: 'LogType',
                          matched: list, filter_text: str,
                          level_filter: set, level_filter_inverted: set,
                          field_filters: dict, field_filters_inverted: set,
                          text_filter_inverted: bool) -> str:
    out      = []
    n_total  = len(data.store)
    n_shown  = len(matched)
    now      = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Header
    out.append('LogAlyzer Stats Export')
    out.append('=' * 54)
    out.append(f'Generated : {now}')
    out.append(f'File      : {data.path}')
    out.append(f'Log type  : {log_type.name}')
    out.append(f'Lines     : {n_shown:,} shown of {n_total:,} total')
    if filter_text:
        inv_tag = ' [INVERTED — excluding matches]' if text_filter_inverted else ''
        out.append(f'Filter    : {filter_text}{inv_tag}')
    if level_filter:
        out.append(f'Levels    : {", ".join(sorted(level_filter))} (show only)')
    if level_filter_inverted:
        out.append(f'Levels    : {", ".join(sorted(level_filter_inverted))} (hidden)')
    for ft, vals in field_filters.items():
        label = next(
            (f.label for f in log_type.stat_fields if f.type == ft), ft)
        inv_tag = ' [INVERTED — excluding]' if any(
            (ft, v) in field_filters_inverted for v in vals) else ''
        out.append(f'Field     : {label} = {", ".join(sorted(vals))}{inv_tag}')
    out.append('')

    def section(title: str, rows: list) -> None:
        out.append(title)
        out.append('-' * len(title))
        out.extend(rows)
        out.append('')

    # Activity histogram
    hist = stats.get('histogram', [])
    if hist:
        max_v = max(c for _, c in hist)
        rows  = [
            f'  {label:>8}  {_bar(count, max_v, chars='#.')}  {count:>7,}'
            for label, count in hist
        ]
        section('Activity over time', rows)

    # Generic panels (in JSON declaration order)
    for label, kind, entries in stats.get('panels', []):
        if not entries:
            continue
        max_v = entries[0][1]
        rows  = []
        for val, count in entries:
            bar     = _bar(count, max_v, chars='#.')
            val_col = val[:_EXPORT_VAL_W]
            rows.append(f'  {val_col:<{_EXPORT_VAL_W}}  {bar}  {count:>7,}')
        section(label, rows)

    if not hist and not stats.get('panels'):
        out.append('No stats available for the current view.')
        out.append('')

    return '\n'.join(out)

# Status Indicator
class StatusIndicator:
    _FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    _BAR_W  = 12

    def __init__(self):
        self._mode  = 'idle'
        self._label = ''
        self._pct   = 0
        self._frame_idx = 0
        self._frame     = self._FRAMES[0]

    def set_idle(self):
        self._mode = 'idle'

    def set_progress(self, label: str, pct: int):
        self._mode  = 'progress'
        self._label = label
        self._pct   = max(0, min(100, pct))

    def set_spinner(self, label: str):
        self._mode  = 'spinner'
        self._label = label

    def tick(self) -> bool:
        self._frame_idx = (self._frame_idx + 1) % len(self._FRAMES)
        self._frame     = self._FRAMES[self._frame_idx]
        return self._mode == 'spinner'

    def render(self, tail_mode: bool) -> list:
        if self._mode == 'progress':
            filled = round(self._pct / 100 * self._BAR_W)
            bar    = '▓' * filled + '░' * (self._BAR_W - filled)
            return [('h_dim', f' {self._label} [{bar}] {self._pct}%')]
        if self._mode == 'spinner':
            return [('h_dim', f' {self._frame} {self._label}…')]
        if tail_mode:
            return [('tail_on', '● LIVE')]
        return [('tail_off', '○ ────')]

# Main Application
class LogApp:
    def __init__(self, data: LogData):
        self.data      = data
        self.log_type  = data.log_type

        self._filter_alarm = None
        self.filter_text = ''
        self.filter_re   = None
        self.filter_err  = False
        self.use_regex   = False
        self.case_sens   = False

        self.show_lineno = True
        self.tail_mode   = False
        self.show_stats  = False

        self.level_filter: set          = set()
        self.level_filter_inverted: set = set()   # levels to hide (blacklist)
        self.field_filters: dict        = {}
        self.field_filters_inverted: set = set()  # field types whose filter is inverted
        self.text_filter_inverted: bool = False   # True → exclude text matches
        self._pending:      dict | None = None
        self.matched:       list        = []
        self._export_status: str        = ''

        self._loop_ref = None

        self._loading  = False
        self._load_pct = 0

        # Docker streaming states mutated only on main-loop thread
        self._streamer:   DockerStreamer | None = None
        self._docker_q:   _queue.SimpleQueue    = _queue.SimpleQueue()
        self._docker_mode: bool                 = False   # True when viewing a container

        self._status     = StatusIndicator()
        self._spin_alarm = None

        self._build_ui()
        self._apply_filter()

    def set_log_type(self, lt: LogType) -> None:
        self.log_type = lt
        self.field_filters.clear()
        self._pending = None
        self.walker.clear_pending()
        self._relabel_pills(lt)
        self._rebuild_field_bar()

        self._status.set_spinner('Applying log type')
        self._refresh_title()

        if not self._loop_ref:
            # Loop not running yet, apply synchronously (file hasn't loaded anyway)
            self.data.store.set_log_type(lt)
            self.data.log_type = lt
            self._status.set_idle()
            self._refresh_title()
            return

        self._start_spinner()

        write_fd = self._loop_ref.watch_pipe(self._on_set_type_pipe)
        result_q: _queue.SimpleQueue = _queue.SimpleQueue()

        def _worker():
            # Read a snapshot of the lines list so the worker only reads;
            # the main thread will apply the result via replace_levels().
            new_levels = [lt.detect_level(self.data.store.get_line(i))
                          for i in range(len(self.data.store))]
            result_q.put(new_levels)
            try:   os.write(write_fd, b'x')
            except OSError: pass

        threading.Thread(target=_worker, daemon=True, name='set-type').start()
        self._set_type_q = result_q

    def _on_set_type_pipe(self, _data: bytes) -> None:
        try:
            new_levels = self._set_type_q.get_nowait()
        except _queue.Empty:
            return
        self.data.store.replace_levels(new_levels)
        self._stop_spinner()
        self._apply_filter()
        try:   self._loop_ref.draw_screen()
        except Exception: pass

    def _relabel_pills(self, lt: LogType) -> None:
        defaults = {'error': 'ERR', 'warn': 'WARN', 'info': 'INFO', 'debug': 'DBG'}
        for key, pill in self.pills.items():
            pill.relabel(lt.level_labels.get(key, defaults[key]))

    # Async loading
    def start_async_load(self, loop) -> None:
        self._loop_ref = loop
        self._status.set_progress('Loading', 0)
        self._refresh_title()
        write_fd = loop.watch_pipe(self._on_load_pipe)

        try:
            sz = os.path.getsize(self.data.path)
        except OSError:
            sz = 1

        def _progress(byte_pos):
            pct = min(99, round(byte_pos / max(1, sz) * 100))
            self._status.set_progress('Loading', pct)
            try:   os.write(write_fd, b'p')
            except OSError: pass

        def _done():
            try:   os.write(write_fd, b'd')
            except OSError: pass

        self.data.load_async(progress_cb=_progress, done_cb=_done)

    def _on_load_pipe(self, data: bytes) -> None:
        self._refresh_title()
        if b'd' in data:
            self._status.set_idle()
            self._refresh_title()
            self._apply_filter()
        try:   self._loop_ref.draw_screen()
        except Exception: pass

    # Build
    def _build_ui(self):
        self.w_title = urwid.Text('', wrap='clip')

        self.w_edit = FilterEdit(caption='')
        urwid.connect_signal(self.w_edit, 'postchange',
                             lambda *_: self._on_edit_change())

        self.cb_regex = urwid.CheckBox('Regex', False,
            on_state_change=lambda w, s: self._cfg(regex=s))
        self.cb_case  = urwid.CheckBox('Case',  False,
            on_state_change=lambda w, s: self._cfg(case=s))
        self.cb_lno   = urwid.CheckBox('#',     True,
            on_state_change=lambda w, s: self._cfg(lno=s))

        def _pad(w):
            return urwid.Padding(w, left=1, right=1)

        self.w_filter_cols = urwid.Columns([
            ('pack', urwid.Text(('fl', ' Filter: '))),
            urwid.AttrMap(self.w_edit, 'fe', 'fe_f'),
            ('pack', _pad(urwid.AttrMap(self.cb_regex, 'fc', 'fc_f'))),
            ('pack', _pad(urwid.AttrMap(self.cb_case,  'fc', 'fc_f'))),
            ('pack', _pad(urwid.AttrMap(self.cb_lno,   'fc', 'fc_f'))),
        ], dividechars=0, focus_column=1)

        # Stats row: level pills + dynamic field filter pills on the same line
        self.w_total   = urwid.Text('')
        self.w_err_msg = urwid.Text('')
        self.pills     = {k: LevelPill(k) for k in ('error', 'warn', 'info', 'debug')}
        for p in self.pills.values():
            urwid.connect_signal(p, 'change', self._on_pill_change)

        # Base contents: field pills are spliced in after w_err_msg by _rebuild_field_bar
        self._stats_base = (
            [('pack', urwid.AttrMap(self.w_total, 'st'))]
            + [('pack', p) for p in self.pills.values()]
            + [('pack', urwid.AttrMap(self.w_err_msg, 'ferr'))]
        )
        self._stats_cols   = urwid.Columns(list(self._stats_base), dividechars=0)
        self._stats_widget = urwid.AttrMap(self._stats_cols, 'st')

        self.w_header = urwid.Pile([
            urwid.AttrMap(self.w_title, 'header'),
            self.w_filter_cols,
            self._stats_widget,
        ])

        self.walker  = LazyListWalker()
        self.listbox = ClickableListBox(self.walker,
                                        click_cb=self._on_line_click)
        self._scrollbar = ClickScrollBar(self.listbox, side='right', width=1,
                                             thumb_char='\u2503', trough_char='\u2502')

        # Body Columns: [log+scrollbar | stats pane]. Pane added/removed by toggle_stats
        self._body_cols = urwid.Columns(
            [self._scrollbar], dividechars=0)
        self._stats_pane_widget = None   # populated when pane is open

        self.w_footer = urwid.Text('', wrap='clip')
        self.frame = urwid.Frame(
            body       = self._body_cols,
            header     = self.w_header,
            footer     = urwid.AttrMap(self.w_footer, 'footer'),
            focus_part = 'body',
        )
        self._refresh_title()
        self._refresh_footer()

    # Refresh
    def _refresh_title(self):
        self.w_title.set_text([
            ('header', ' ◉  LogAlyzer  '),
            ('h_dim',  self.data.display_name),
            ('header', f'  [{self.log_type.name}]  '),
            *self._status.render(self.tail_mode),
        ])

    def _start_spinner(self):
        if self._spin_alarm is None and hasattr(self, '_loop_ref'):
            self._spin_alarm = self._loop_ref.set_alarm_in(0.1, self._on_spin_tick)

    def _stop_spinner(self):
        if self._spin_alarm is not None:
            self._loop_ref.remove_alarm(self._spin_alarm)
            self._spin_alarm = None
        self._status.set_idle()
        self._refresh_title()

    def _on_spin_tick(self, loop, _):
        if self._status.tick():
            self._refresh_title()
            self._spin_alarm = loop.set_alarm_in(0.1, self._on_spin_tick)
        else:
            self._spin_alarm = None

    def _refresh_footer(self):
        # Pending click selection: override footer with confirmation prompt
        if self._pending:
            p = self._pending
            self.w_footer.set_text([
                ('fk',     '  Esc'), ('footer', ':cancel  '),
                ('footer', '  \u25c8 '),
                ('fl',     f'{p["label"]}: '),
                ('hsel',   f' {p["value"][:40]} '),
                ('footer', '  \u2190 click again to filter'),
            ])
            return

        n  = len(self.data.store)
        m  = len(self.matched)
        lf = (f' (+{"+".join(sorted(self.level_filter))})' if self.level_filter else '')
        ff_parts = []
        for ft, vals in self.field_filters.items():
            label = next((f.label for f in self.log_type.stat_fields
                          if f.type == ft), ft)
            ff_parts.append(f'{label}:{"|".join(sorted(vals))}')
        ff = (' (' + ', '.join(ff_parts) + ')') if ff_parts else ''

        export_info = ([('footer', f'  {self._export_status}')]
                       if self._export_status else [])

        self.w_footer.set_text([
            ('fk', '  q'),   ('footer', ':quit  '),
            ('fk', '/'),     ('footer', ':filter  '),
            ('fk', 't'),     ('footer', ':tail  '),
            ('fk', 's'),     ('footer', ':stats  '),
            ('fk', 'e'),     ('footer', ':export  '),
            ('fk', 'd'),     ('footer', ':docker  '),
            ('fk', 'Esc'),   ('footer', ':clear  '),
            ('fk', 'g'),     ('footer', '/'),
            ('fk', 'G'),     ('footer', ':top/btm  '),
            ('footer', '  right-click pill/level = invert filter  '),
            ('footer', f'  {m:,} / {n:,} lines{lf}{ff}'),
            *export_info,
        ])

    def _refresh_stats(self):
        ac = self.data.level_counts()
        n  = len(self.data.store)
        self.w_total.set_text(f' Total {n:,}  ')
        for key, pill in self.pills.items():
            pill.update(ac.get(key, 0))
        self.w_err_msg.set_text('  \u26a0 invalid regex' if self.filter_err else '')

    # Filter
    def _on_edit_change(self):
        self.filter_text = self.w_edit.get_edit_text()
        # Update the filter pill immediately (before the debounced _apply_filter fires)
        # so the pill text stays in sync with what the user is typing.
        self._rebuild_field_bar()

        if not hasattr(self, '_loop_ref') or self._loop_ref is None:
            self._apply_filter()
            return

        if self._filter_alarm is not None:
            self._loop_ref.remove_alarm(self._filter_alarm)
            self._filter_alarm = None

        self._filter_alarm = self._loop_ref.set_alarm_in(
            0.15,
            self._on_filter_alarm
        )
    
    def _on_filter_alarm(self, loop, user_data):
        self._filter_alarm = None
        self._apply_filter()

    def _on_pill_change(self, pill: LevelPill, active: bool):
        if active:
            if pill.inverted:
                # Blacklist mode: remove from whitelist, add to blacklist
                self.level_filter.discard(pill.level_key)
                self.level_filter_inverted.add(pill.level_key)
            else:
                # Whitelist mode: remove from blacklist, add to whitelist
                self.level_filter_inverted.discard(pill.level_key)
                self.level_filter.add(pill.level_key)
        else:
            self.level_filter.discard(pill.level_key)
            self.level_filter_inverted.discard(pill.level_key)
        self._apply_filter()

    def _cfg(self, regex=None, case=None, lno=None):
        if regex is not None: self.use_regex   = regex
        if case  is not None: self.case_sens   = case
        if lno   is not None: self.show_lineno = lno
        self._apply_filter()

    def _apply_filter(self):
        text  = self.filter_text
        store = self.data.store
        lf    = self.level_filter
        lf_i  = self.level_filter_inverted
        ff    = self.field_filters
        ff_i  = self.field_filters_inverted
        t_inv = self.text_filter_inverted

        if text:
            flags = 0 if self.case_sens else re.IGNORECASE
            try:
                pat             = re.compile(
                    text if self.use_regex else re.escape(text), flags)
                self.filter_re  = pat
                self.filter_err = False
            except re.error:
                pat             = None
                self.filter_re  = None
                self.filter_err = True
        else:
            pat             = None
            self.filter_re  = None
            self.filter_err = False

        """
        Pre-build field lookup for field_filters so we're not searching per line.
        Inversion is tracked per (field_type, value) pair, so split each field's
        values into an include-set (must match one) and an exclude-set (must not match).
        """

        ff_fields = {}
        if ff:
            for ft, values in ff.items():
                f = next((f for f in self.log_type.stat_fields if f.type == ft), None)
                if f:
                    include_vals = {v for v in values if (ft, v) not in ff_i}
                    exclude_vals = {v for v in values if (ft, v) in ff_i}
                    ff_fields[ft] = (f, include_vals, exclude_vals)

        matched = []
        for i in range(len(store)):
            line, lvl = store[i]
            # Level whitelist: if any levels are whitelisted, line's level must be in the set
            if lf and lvl not in lf:
                continue
            # Level blacklist: if any levels are blacklisted, line's level must NOT be in the set
            if lf_i and lvl in lf_i:
                continue
            # Text filter (normal = must match; inverted = must NOT match)
            if pat:
                match = pat.search(line)
                if t_inv:
                    if match:     continue   # inverted: skip lines that match
                else:
                    if not match: continue   # normal: skip lines that don't match
            # Field filters: each value is independently normal or inverted
            if ff_fields:
                ok = True
                for ft, (f, include_vals, exclude_vals) in ff_fields.items():
                    val = f.extract(line)
                    if include_vals and val not in include_vals: ok = False; break
                    if exclude_vals and val in exclude_vals:     ok = False; break
                if not ok:
                    continue
            matched.append(i)

        self.matched = matched
        self._rebuild_view()
        self._rebuild_field_bar()
        self._refresh_stats()
        self._refresh_footer()

    def _rebuild_view(self):
        self.walker.reset(
            self.data.store,
            self.log_type, self.show_lineno,
            self.filter_re, self.matched,
        )
        # Re-apply pending selection if one is active (reset clears the cache)
        if self._pending:
            p = self._pending
            self.walker.set_pending(p['raw_idx'], p['start'], p['end'])
        if self.tail_mode and self.matched:
            self.listbox.focus_position = len(self.matched) - 1

    # Actions
    def toggle_tail(self):
        self.tail_mode = not self.tail_mode
        self._refresh_title()
        if self.tail_mode and self.walker:
            self.listbox.focus_position = len(self.walker) - 1

    def toggle_stats(self):
        self.show_stats = not self.show_stats
        if self.show_stats:
            self._open_stats_pane()
        else:
            self._close_stats_pane()

    def _open_stats_pane(self):
        placeholder = build_stats_pane({}, ' (computing…)')
        self._stats_pane_widget = placeholder
        self._body_cols.contents = [
            (self._scrollbar,  self._body_cols.options('weight', 1)),
            (placeholder,      self._body_cols.options('given',  STATS_WIDTH)),
        ]

        self._status.set_spinner('Computing stats')
        self._refresh_title()
        self._start_spinner()

        write_fd = self._loop_ref.watch_pipe(self._on_stats_pipe)
        result_q: _queue.SimpleQueue = _queue.SimpleQueue()

        store   = self.data.store
        matched = list(self.matched)
        lt      = self.log_type

        def _worker():
            stats = compute_stats(store, matched, log_type=lt)
            result_q.put(stats)
            try:   os.write(write_fd, b'x')
            except OSError: pass

        threading.Thread(target=_worker, daemon=True, name='stats').start()
        self._stats_q = result_q

    def _on_stats_pipe(self, _data: bytes) -> None:
        try:
            stats = self._stats_q.get_nowait()
        except _queue.Empty:
            return
        suffix = f' ({len(self.matched):,} lines)' if self.filter_text or self.level_filter else ''
        pane   = build_stats_pane(stats, suffix)
        self._stats_pane_widget = pane
        if self.show_stats:
            self._body_cols.contents = [
                (self._scrollbar, self._body_cols.options('weight', 1)),
                (pane,            self._body_cols.options('given', STATS_WIDTH)),
            ]
        self._stop_spinner()
        try:   self._loop_ref.draw_screen()
        except Exception: pass

    def _close_stats_pane(self):
        self._stats_pane_widget = None
        self._body_cols.contents = [
            (self._scrollbar, self._body_cols.options('weight', 1)),
        ]

    def focus_filter(self):
        self.frame.focus_position = 'header'
        try:    self.w_header.focus_position = 1
        except Exception: pass
        try:    self.w_filter_cols.focus_position = 1
        except Exception: pass

    def clear_filter(self):
        # Clear level pills (both whitelist and blacklist)
        self.level_filter.clear()
        self.level_filter_inverted.clear()
        for p in self.pills.values():
            p.reset()
        # Clear field filters (including inversion flags) and any pending selection
        self.field_filters.clear()
        self.field_filters_inverted.clear()
        self.text_filter_inverted = False
        self._pending = None
        self.walker.clear_pending()
        self._rebuild_field_bar()
        self.w_edit.set_edit_text('')       # triggers _on_edit_change → _apply_filter
        self.frame.focus_position = 'body'

    def go_top(self):
        if self.walker:
            self.listbox.focus_position = 0

    def go_bottom(self):
        if self.walker:
            self.listbox.focus_position = len(self.walker) - 1

    def export_stats(self) -> None:
        # Write stats for the current view to a timestamped .txt file in cwd.
        stats = compute_stats(self.data.store, self.matched, log_type=self.log_type)
        text = export_stats_to_text(
            stats,
            data                   = self.data,
            log_type               = self.log_type,
            matched                = self.matched,
            filter_text            = self.filter_text,
            level_filter           = self.level_filter,
            level_filter_inverted  = self.level_filter_inverted,
            field_filters          = self.field_filters,
            field_filters_inverted = self.field_filters_inverted,
            text_filter_inverted   = self.text_filter_inverted,
        )
        ts    = datetime.now().strftime('%Y%m%d_%H%M%S')
        fname = f'logalyzer_stats_{ts}.txt'
        fpath = os.path.join(os.getcwd(), fname)
        try:
            with open(fpath, 'w', encoding='utf-8') as fh:
                fh.write(text)
            self._export_status = f'exported -> {fname}'
        except OSError as exc:
            self._export_status = f'export failed: {exc}'
        self._refresh_footer()

    def ingest_new(self, new_lines: list):
        store    = self.data.store
        n_before = len(store) - len(new_lines)
        lf       = self.level_filter
        fre      = self.filter_re
        to_add   = []
        for j, line in enumerate(new_lines):
            i   = n_before + j
            lvl = store.get_level(i)
            if lf and lvl not in lf:
                continue
            if fre and not fre.search(line):
                continue
            to_add.append(i)
        if not to_add:
            return
        self.matched.extend(to_add)
        self._rebuild_view()
        self._refresh_stats()
        self._refresh_footer()

    # Docker

    def open_docker_selector(self, loop, push_overlay_cb, pop_overlay_cb) -> None:
        """
        Fetches the container list in a
        background thread; updates the overlay in-place when done.
        Everything that touches urwid widgets runs on the main-loop thread
        via a watch_pipe callback.
        """
        self._pop_overlay  = pop_overlay_cb
        self._push_overlay = push_overlay_cb

        # Show spinner
        overlay = make_docker_selector_overlay(
            self.frame, 'loading', [], '',
            on_select=self._on_docker_container_selected,
            on_cancel=pop_overlay_cb,
        )
        push_overlay_cb(overlay)

        fetch_q:   _queue.SimpleQueue = _queue.SimpleQueue()
        write_fd = loop.watch_pipe(
            lambda _: self._on_docker_fetch_pipe(fetch_q, push_overlay_cb, pop_overlay_cb))

        def _fetch():
            try:
                containers = docker_list_containers()
                fetch_q.put(('ok', containers))
            except Exception as exc:
                fetch_q.put(('error', str(exc)))
            try:   os.write(write_fd, b'x')
            except OSError: pass

        threading.Thread(target=_fetch, daemon=True, name='docker-fetch').start()

    def _on_docker_fetch_pipe(self, fetch_q: _queue.SimpleQueue,
                               push_overlay_cb, pop_overlay_cb) -> None:
        # Main-loop-thread callback: drain the fetch queue and refresh overlay.
        try:
            kind, payload = fetch_q.get_nowait()
        except _queue.Empty:
            return

        if kind == 'ok':
            overlay = make_docker_selector_overlay(
                self.frame, 'ready', payload, '',
                on_select=self._on_docker_container_selected,
                on_cancel=pop_overlay_cb,
            )
        else:
            overlay = make_docker_selector_overlay(
                self.frame, 'error', [], payload,
                on_select=self._on_docker_container_selected,
                on_cancel=pop_overlay_cb,
            )
        push_overlay_cb(overlay)

    def _on_docker_container_selected(self, container: dict) -> None:
        # Stop any existing streamer, reset LogData, and start streaming the selected container.
        if self._streamer is not None:
            self._streamer.stop()
            self._streamer = None

        # Fresh LogData
        log_types  = load_log_types()
        plain_type = next((lt for lt in log_types if lt.id == 'other'), log_types[-1])

        display    = container['name'] or container['short_id']
        new_data   = LogData(f"docker://{container['id']}", plain_type,
                             display_name=f"\u2692 {display}")
        self.data         = new_data
        self.log_type     = plain_type
        self._docker_mode = True
        self.tail_mode    = True
        # Buffer for auto-detection; cleared once detection fires
        self._docker_detect_buf: list = []
        self._docker_detected:   bool = False
        self._docker_log_types        = log_types
        self._docker_image_hint       = container['image'].split(':')[0].split('/')[-1]

        # Reset view state
        self.field_filters.clear()
        self._pending = None
        self.walker.clear_pending()
        self.matched  = []
        self._relabel_pills(plain_type)
        self._rebuild_view()
        self._refresh_title()
        self._refresh_stats()
        self._refresh_footer()

        # Dismiss overlay
        self._pop_overlay()

        # Start streaming
        streamer = DockerStreamer(
            container['id'], self._docker_q, self._docker_write_fd,
            tail=2000,
        )
        self._streamer = streamer
        streamer.start()

    def attach_docker_pipe(self, write_fd: int) -> None:
        # Called once from main() so the app knows its docker wakeup fd.
        self._docker_write_fd = write_fd

    def on_docker_pipe(self, _data: bytes) -> None:
        """
        Main-loop-thread callback: drain the docker queue and ingest lines.
        This is the only point where docker thread output enters urwid state.
        """
        batch = []
        while True:
            try:
                kind, payload = self._docker_q.get_nowait()
            except _queue.Empty:
                break
            if kind == 'line':
                batch.append(payload)
            elif kind == 'eof':
                self.tail_mode = False
                self._refresh_title()
            elif kind == 'error':
                self._export_status = f'\u26a0 Docker: {payload}'
                self._refresh_footer()

        if not batch:
            return

        # Auto-detect log type from first arriving lines
        if not getattr(self, '_docker_detected', True):
            self._docker_detect_buf.extend(batch)
            if len(self._docker_detect_buf) >= 20:
                detected = auto_detect(
                    self._docker_image_hint,
                    self._docker_detect_buf,
                    self._docker_log_types,
                )
                self._docker_detected = True
                self.log_type = detected
                self.data.set_type(detected)
                self._relabel_pills(detected)
                self._refresh_title()
                # Flush the entire buffer as one batch
                batch = list(self._docker_detect_buf)
                self._docker_detect_buf = []
            else:
                pass

        self._ingest_docker_lines(batch)

    def _ingest_docker_lines(self, new_lines: list) -> None:
        # Append lines to LogData, enforce DOCKER_MAX_LINES cap, and update the view.
        for line in new_lines:
            self.data.store.append(line)   # classifies and appends atomically

        overflow = len(self.data.store) - DOCKER_MAX_LINES
        if overflow > 0:
            # Trim from front; all stored indices shift — full rebuild required
            self.data.store.trim_front(overflow)
            self._apply_filter()
        else:
            # Fast path: only append newly-matched indices
            store    = self.data.store
            n_before = len(store) - len(new_lines)
            lf       = self.level_filter
            fre      = self.filter_re
            to_add   = []
            for j, line in enumerate(new_lines):
                i   = n_before + j
                lvl = store.get_level(i)
                if lf and lvl not in lf:
                    continue
                if fre and not fre.search(line):
                    continue
                to_add.append(i)
            if to_add:
                self.matched.extend(to_add)
                self._rebuild_view()

        self._refresh_stats()
        self._refresh_footer()

        if self.tail_mode and self.matched:
            self.listbox.focus_position = len(self.matched) - 1

    # Click-to-filter
    def _on_line_click(self, walker_pos: int, col: int) -> bool:
        # Called by ClickableListBox on left-click. Returns True if consumed.
        if walker_pos >= len(self.matched):
            return False
        raw_idx = self.matched[walker_pos]
        line    = self.data.store.get_line(raw_idx)

        lno_prefix_w = len(f'{raw_idx + 1:6d} \u2502 ') if self.show_lineno else 0
        raw_col = col - lno_prefix_w

        if raw_col < 0:
            self._cancel_pending()
            return True

        hit = self._hit_test(line, raw_col)

        if self._pending is not None:
            p = self._pending
            if (hit is not None
                    and hit['field_type'] == p['field_type']
                    and hit['value']      == p['value']
                    and raw_idx           == p['raw_idx']):
                self._confirm_pending()
                return True
            else:
                self._cancel_pending()

        if hit is not None:
            self._set_pending(raw_idx, hit)
            return True

        return False

    def _hit_test(self, line: str, raw_col: int) -> dict | None:
        # Return the first filterable field whose captured span contains raw_col.
        for f in self.log_type.stat_fields:
            if not f.filterable:
                continue
            result = f.extract_with_span(line)
            if result is None:
                continue
            val, start, end = result
            if start <= raw_col < end:
                return {
                    'field_type': f.type,
                    'label':      f.label,
                    'value':      val,
                    'start':      start,
                    'end':        end,
                }
        return None

    def _set_pending(self, raw_idx: int, hit: dict) -> None:
        self._pending = {**hit, 'raw_idx': raw_idx}
        self.walker.set_pending(raw_idx, hit['start'], hit['end'])
        self._rebuild_field_bar()
        self._refresh_footer()

    def _cancel_pending(self) -> None:
        if self._pending is None:
            return
        self._pending = None
        self.walker.clear_pending()
        self._rebuild_field_bar()
        self._refresh_footer()

    def _confirm_pending(self) -> None:
        p  = self._pending
        ft = p['field_type']
        if ft not in self.field_filters:
            self.field_filters[ft] = set()
        self.field_filters[ft].add(p['value'])
        self._pending = None
        self.walker.clear_pending()
        self._apply_filter()
        self._rebuild_field_bar()

    def _rebuild_field_bar(self) -> None:
        """
        Splice field filter pills + pending preview into the stats Columns row.
        Header height never changes, so the second click lands on the same line.
        """
        extra = []
        if self.filter_text and not self.filter_err:
            label = 're' if self.use_regex else '~'
            fp = FieldPill('_text_filter', label, self.filter_text,
                           inverted=self.text_filter_inverted)
            urwid.connect_signal(fp, 'remove',        self._on_field_pill_remove)
            urwid.connect_signal(fp, 'toggle_invert', self._on_field_pill_invert)
            extra.append(('pack', fp))

        # Active field filter pills
        for ft, values in self.field_filters.items():
            label  = next((f.label for f in self.log_type.stat_fields
                           if f.type == ft), ft)
            for val in sorted(values):
                is_inv = (ft, val) in self.field_filters_inverted
                fp = FieldPill(ft, label, val, inverted=is_inv)
                urwid.connect_signal(fp, 'remove',        self._on_field_pill_remove)
                urwid.connect_signal(fp, 'toggle_invert', self._on_field_pill_invert)
                extra.append(('pack', fp))

        # Pending selection preview pill
        if self._pending:
            p = self._pending
            preview = urwid.AttrMap(
                urwid.Text(f' \u25c8{p["label"]}:{p["value"][:24]} ? ', wrap='clip'),
                'hsel')
            extra.append(('pack', preview))

        # Replace Columns contents in-place: no Pile row added/removed
        self._stats_cols.contents = (
            [(w, self._stats_cols.options('pack')) for _, w in self._stats_base]
            + [(w, self._stats_cols.options('pack')) for _, w in extra]
        )

    def _on_field_pill_invert(self, pill: FieldPill) -> None:
        # Right-click on a pill: toggle inclusion ↔ exclusion for its filter value.
        if pill.field_type == '_text_filter':
            self.text_filter_inverted = not self.text_filter_inverted
        else:
            key = (pill.field_type, pill.value)
            if key in self.field_filters_inverted:
                self.field_filters_inverted.discard(key)
            else:
                self.field_filters_inverted.add(key)
        self._apply_filter()
        self._rebuild_field_bar()

    def _on_field_pill_remove(self, pill: FieldPill) -> None:
        if pill.field_type == '_text_filter':
            self.text_filter_inverted = False
            self.w_edit.set_edit_text('')
            return
        ft  = pill.field_type
        val = pill.value
        if ft in self.field_filters:
            self.field_filters[ft].discard(val)
            self.field_filters_inverted.discard((ft, val))
            if not self.field_filters[ft]:
                del self.field_filters[ft]
        self._apply_filter()
        self._rebuild_field_bar()


# Live-tail thread
def _tail_worker(poll_cb, ingest_cb, is_active_cb, write_fd: int):
    """
    File-tail polling worker; runs in a daemon thread.

    poll_cb()      -> list of new lines appended to LogData
    ingest_cb(new) -> called from worker thread (known race with urwid state)
    is_active_cb() -> returns True when tail mode is on and not in docker mode
    """
    while True:
        time.sleep(0.5)
        if not is_active_cb():
            continue
        new = poll_cb()
        if new:
            ingest_cb(new)
            try:
                os.write(write_fd, b'x')
            except OSError:
                break


# Entry point
def main():
    ap = argparse.ArgumentParser(
        description='LogAlyzer \u2014 Terminal log analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('-f', '--file',   metavar='PATH', help='Log file to open')
    src.add_argument('-d', '--docker', action='store_true',
                     help='Connect to Docker and select a container')
    args = ap.parse_args()

    if not docker_available() and args.docker:
        sys.exit('Error: Docker socket not found at /var/run/docker.sock')

    log_types  = load_log_types()
    plain_type = next((lt for lt in log_types if lt.id == 'other'), log_types[-1])

    file_mode   = bool(args.file)
    docker_mode = args.docker

    if file_mode:
        path = args.file
        if not os.path.isfile(path):
            sys.exit(f'Error: {path!r} not found.')
        with open(path, errors='replace') as fh:
            preview = [fh.readline().rstrip('\n') for _ in range(50)]
        detected = auto_detect(path, preview, log_types)
        data = LogData(path, detected)
    else:
        detected = plain_type
        data = LogData('', plain_type, display_name='(connecting to Docker\u2026)')

    app = LogApp(data)

    loop_ref: list = []

    # Overlay manager
    _active_overlay: list = [None]
    logtype_overlay: list = [None]

    def push_overlay(ov):
        _active_overlay[0] = ov
        if loop_ref:
            loop_ref[0].widget = ov

    def pop_overlay():
        _active_overlay[0] = None
        if loop_ref:
            loop_ref[0].widget = app.frame

    def on_type_selected(lt: LogType):
        app.set_log_type(lt)
        pop_overlay()

    if file_mode:
        ov = make_selector_overlay(app.frame, log_types, detected, on_type_selected)
        logtype_overlay[0] = ov
        push_overlay(ov)
        initial_widget = ov
    else:
        initial_widget = app.frame

    # Input handler
    def handle_input(key: str):
        if _active_overlay[0] is not None:
            if key == 'esc':
                if _active_overlay[0] is logtype_overlay[0]:
                    on_type_selected(detected)
                else:
                    pop_overlay()
            return

        if key == 'esc' and app._pending is not None:
            app._cancel_pending()
            return

        if   key in ('q', 'Q'):
            if app._streamer is not None:
                app._streamer.stop()
            raise urwid.ExitMainLoop()
        elif key == '/':
            app.focus_filter()
        elif key in ('esc', 'enter'):
            if app.frame.focus_position == 'header':
                if key == 'esc':
                    app.clear_filter()
                else:
                    app.frame.focus_position = 'body'
            elif key == 'esc':
                app.clear_filter()
        elif key in ('t', 'T'):
            app.toggle_tail()
        elif key in ('s', 'S'):
            app.toggle_stats()
        elif key == 'g':
            app.go_top()
        elif key == 'G':
            app.go_bottom()
        elif key in ('e', 'E'):
            app.export_stats()
        elif key in ('d', 'D'):
            if loop_ref:
                app.open_docker_selector(loop_ref[0], push_overlay, pop_overlay)

    loop = urwid.MainLoop(
        initial_widget,
        palette         = PALETTE,
        unhandled_input = handle_input,
        handle_mouse    = True,
    )
    loop_ref.append(loop)

    app._loop_ref = loop

    docker_write_fd = loop.watch_pipe(app.on_docker_pipe)
    app.attach_docker_pipe(docker_write_fd)

    if file_mode:
        app.start_async_load(loop)

    tail_write_fd = loop.watch_pipe(lambda _: loop.draw_screen())
    threading.Thread(
        target=_tail_worker,
        args=(
            app.data.poll_new,
            app.ingest_new,
            lambda: app.tail_mode and not app._docker_mode,
            tail_write_fd,
        ),
        daemon=True,
    ).start()

    if docker_mode:
        def _open_docker_on_start(loop, user_data):
            app.open_docker_selector(loop, push_overlay, pop_overlay)
        loop.set_alarm_in(0.05, _open_docker_on_start)

    loop.run()


if __name__ == '__main__':
    main()