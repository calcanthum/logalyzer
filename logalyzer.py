#!/usr/bin/env python3
"""
logalyzer.py — Terminal log analyzer with mouse support

Usage:    python logalyzer.py -f <logfile>
          python logalyzer.py -d
          python logalyzer.py -F <FIFO>

Keys:
  /         focus filter bar
  Enter     return to log view
  Esc       clear filter + level pills + field filters, return to log view
  t         toggle live tail
  s         toggle stats panel
  l         change logtype
  e         export current stats
  d         open Docker container selector
  g / G     jump to top / bottom
  q         quit

Mouse:    scroll wheel navigates the log; click level pills to filter
          click a field value in a log line to start a field filter (two-click confirm)
          double left click on a field pill to remove that filter
          right click on a field pill to invert that filter

Log type definitions live in ./logtypes/*.json — copy and edit to add custom types.
"""
from __future__ import annotations
import curses
import re
import os
import stat
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
    # stats pills — inverted / blacklist mode
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
    # inline highlights (used by logtype JSON)
    ('he',       'light red,bold',    'default'),
    ('hw',       'yellow,bold',       'default'),
    ('hi',       'light green,bold',  'default'),
    ('hd',       'dark cyan,bold',    'default'),
    ('hip',      'light cyan',        'default'),
    ('h2ok',     'light green',       'default'),
    ('h3xx',     'yellow',            'default'),
    ('h4xx',     'light red',         'default'),
    ('hm',       'black',             'yellow'),
    ('hsel',     'black,bold',        'dark cyan'),
    ('lno',      'dark gray',         'default'),
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
    ('fpill_n',  'dark cyan',           'dark gray'),
    ('fpill_a',  'black,bold',          'dark cyan'),
    ('fpill_inv','light red',           'dark gray'),
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

_URWID_FG_MAP = {
    'black':         curses.COLOR_BLACK,
    'dark red':      curses.COLOR_RED,
    'dark green':    curses.COLOR_GREEN,
    'brown':         curses.COLOR_YELLOW,
    'dark blue':     curses.COLOR_BLUE,
    'dark magenta':  curses.COLOR_MAGENTA,
    'dark cyan':     curses.COLOR_CYAN,
    'light gray':    curses.COLOR_WHITE,
    'dark gray':     8,
    'light red':     9,
    'light green':   10,
    'yellow':        11,
    'light blue':    12,
    'light magenta': 13,
    'light cyan':    14,
    'white':         15,
    'default':       -1,
}

COLOR_PAIRS: dict[str, int] = {}


def init_colors(no_color: bool = False) -> None:
    if no_color:
        for name, _, _ in PALETTE:
            COLOR_PAIRS[name] = curses.A_NORMAL
        return

    curses.start_color()
    curses.use_default_colors()

    for idx, (name, fg_spec, bg_spec) in enumerate(PALETTE, start=1):
        parts = [p.strip() for p in fg_spec.split(',')]
        fg_name = parts[0]
        bold    = 'bold' in parts

        fg = _URWID_FG_MAP.get(fg_name, -1)
        bg = _URWID_FG_MAP.get(bg_spec.strip(), -1)

        try:
            curses.init_pair(idx, fg, bg)
        except curses.error:
            pass

        attr = curses.color_pair(idx)
        if bold:
            attr |= curses.A_BOLD
        COLOR_PAIRS[name] = attr

    COLOR_PAIRS.setdefault('default', curses.A_NORMAL)


def _attr(name: str) -> int:
    return COLOR_PAIRS.get(name, curses.A_NORMAL)


LOGTYPE_DIR      = Path(__file__).parent / 'logtypes'
DOCKER_SOCKET    = '/var/run/docker.sock'
DOCKER_MAX_LINES = 100_000

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

_RE_PATH_ID = re.compile(r'/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27})(?=/|$)', re.I)


def _normalize_path(path: str) -> str:
    return _RE_PATH_ID.sub('/{id}', path)

_UNK_PAIR_OPEN  = {'[': ']', '{': '}', '(': ')'}
_UNK_PAIR_CLOSE = {v: k for k, v in _UNK_PAIR_OPEN.items()}
_UNK_PAIR_QUOTE = ('"', "'")
_UNK_CANDIDATE_DELIMS = ['|', ',', ';', '\t', ' ']


def _unk_count_delim(line: str, delim: str) -> int:
    depth = 0
    in_quote: str | None = None
    count = 0
    i = 0
    n = len(line)
    dlen = len(delim)
    while i < n:
        ch = line[i]
        if in_quote:
            if ch == in_quote:
                in_quote = None
        elif ch in _UNK_PAIR_QUOTE and depth == 0:
            in_quote = ch
        elif ch in _UNK_PAIR_OPEN:
            depth += 1
        elif ch in _UNK_PAIR_CLOSE and depth > 0:
            depth -= 1
        elif depth == 0:
            if line[i:i + dlen] == delim:
                count += 1
                i += dlen
                continue
        i += 1
    return count

def _unk_split(line: str, delim: str) -> list:
    fields: list = []
    depth    = 0
    in_quote: str | None = None
    fs       = 0          # current field start offset
    i        = 0
    n        = len(line)
    dlen     = len(delim)
    space    = (delim == ' ')

    def _emit(raw_start: int, raw_end: int) -> None:
        raw = line[raw_start:raw_end]
        val = raw.strip()
        # Strip the outermost pair chars so the stored value is clean.
        if len(val) >= 2:
            if val[0] in _UNK_PAIR_OPEN and val[-1] == _UNK_PAIR_OPEN[val[0]]:
                val = val[1:-1].strip()
            elif val[0] in _UNK_PAIR_QUOTE and val[-1] == val[0]:
                val = val[1:-1]
        if val:
            fields.append((val, raw_start, raw_end))

    while i < n:
        ch = line[i]
        if in_quote:
            if ch == in_quote:
                in_quote = None
            i += 1
            continue
        if ch in _UNK_PAIR_QUOTE and depth == 0:
            in_quote = ch
            i += 1
            continue
        if ch in _UNK_PAIR_OPEN:
            depth += 1
            i += 1
            continue
        if ch in _UNK_PAIR_CLOSE and depth > 0:
            depth -= 1
            i += 1
            continue
        if depth == 0:
            if space and ch == ' ':
                _emit(fs, i)
                i += 1
                while i < n and line[i] == ' ':
                    i += 1
                fs = i
                continue
            if not space and line[i:i + dlen] == delim:
                _emit(fs, i)
                fs = i + dlen
                i += dlen
                continue
        i += 1

    _emit(fs, n)
    return fields

def _unk_split_best(line: str, primary: str) -> list:
    fields = _unk_split(line, primary)
    if len(fields) > 1:
        return fields
    best = fields
    for delim in _UNK_CANDIDATE_DELIMS:
        if delim == primary:
            continue
        candidate = _unk_split(line, delim)
        if len(candidate) > len(best):
            best = candidate
    return best

def _unk_detect_delimiter(lines: list) -> str:
    sample = [l for l in lines if l.strip()][:50]
    if not sample:
        return ' '

    best_delim = ' '
    best_score = -1.0

    for delim in _UNK_CANDIDATE_DELIMS:
        counts   = [_unk_count_delim(l, delim) for l in sample]
        mean     = sum(counts) / len(counts)
        if mean < 1.0:
            continue
        # Fraction of lines containing at least one occurrence.
        coverage = sum(1 for c in counts if c >= 1) / len(counts)
        if coverage < 0.5:
            continue
        penalty  = 0.7 if delim == ' ' else 1.0
        score    = mean * coverage * penalty
        if score > best_score:
            best_score = score
            best_delim = delim

    return best_delim

def _parse_ts(raw: str, strptime_fmt: str | None = None):
    if strptime_fmt:
        try:
            return datetime.strptime(raw, strptime_fmt).replace(tzinfo=None)
        except ValueError:
            pass
    return _extract_ts(raw)


def _extract_ts(line: str):
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
    if isinstance(ts, datetime):
        if span_secs <= 3600:
            return ts.strftime('%H:%M')
        elif span_secs <= 86400:
            return ts.strftime('%d %H:00')
        else:
            return ts.strftime('%m-%d')
    else:
        if span_secs <= 60:
            return f'{int(ts):4d}s'
        return f'{int(ts)//60:3d}m'

# Stats engine
def compute_stats(store, indices: list, log_type=None, n_top: int = 8):
    # Compute activity histogram and top-N value counts for each filterable field over the given line indices.
    fields       = getattr(log_type, 'stat_fields', [])
    field_by_type = {f.type: f for f in fields}

    timestamps: list = []
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

    return {'histogram': histogram, 'panels': panels}


# Highlight engine

def _hl(tokens: list, pattern: re.Pattern, attr: str, base_only: bool = True) -> list:
    # base_only prevents later highlights from overwriting earlier, more-specific ones
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
    # absolute character offsets from click hit-testing not regex
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


# Log type classes

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
        self.buckets      = d.get('buckets', [])
        self.components   = d.get('components', [])
        self.format       = d.get('format', '')
        self.filterable   = d.get('filterable', False)
        self.strptime     = d.get('strptime', None)

    def extract(self, line: str):
        if self.multi:
            return self.re.findall(line) if self.re else []
        result = self.extract_with_span(line)
        return result[0] if result else None

    def extract_with_span(self, line: str):
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
        self.level_labels: dict = d.get('level_labels', {})
        self._combined_re, self._combined_map = self._build_combined_re()
        self.stat_fields: list = [StatField(f) for f in d.get('fields', [])]

    def _build_combined_re(self):
        if not self.level_rules:
            return None, {}
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
            except re.error:
                return None, {}

    def score(self, path: str, lines: list) -> int:
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
            toks = _hl(toks, search_re, 'hm', base_only=False)
        pfx  = [('lno', f'{lineno:6d} \u2502 ')] if lineno is not None else []
        return pfx + toks

    def filterable_spans(self, line: str) -> list:
        # Return [(start, end), ...] character ranges for all filterable fields.
        spans = []
        for f in self.stat_fields:
            if not f.filterable:
                continue
            result = f.extract_with_span(line)
            if result:
                _, start, end = result
                spans.append((start, end))
        return spans

    def analyze(self, lines: list) -> None:
        # No-op for typed log types; overridden by UnknownLogType.
        pass

class PositionalField:
    # dynamic field for UnknownLogType


    def __init__(self, idx: int, label: str, delim: str,
                 dtype: str = 'text') -> None:
        self.type         = f'field_{idx}'
        self.label        = label
        self.dtype        = dtype        # 'timestamp' for the auto-detected ts column
        self._idx         = idx
        self._delim       = delim
        # StatField interface attrs expected by compute_stats / _apply_filter
        self.multi        = False
        self.normalize    = False
        self.error_levels: set = set()   # empty → all levels included
        self.filterable   = True
        self.buckets: list = []
        self.components: list = []
        self.format       = ''
        self.strptime     = None
        self.re           = None         # not regex-based

    def extract(self, line: str):
        r = self.extract_with_span(line)
        return r[0] if r else None

    def extract_with_span(self, line: str):
        fields = _unk_split_best(line, self._delim)
        if self._idx < len(fields):
            val, start, end = fields[self._idx]
            return val, start, end
        return None


class UnknownLogType(LogType):
    def __init__(self) -> None:
        super().__init__({
            'id':          'unknown',
            'name':        'Unknown / Generic (auto-delimit)',
            'detect':      {},
            'level_rules': [],
            'highlights':  [],
        })
        self._delim    = ' '
        self._analyzed = False

    def filterable_spans(self, line: str) -> list:
        if not self._analyzed:
            return []
        return [(start, end)
                for _, start, end in _unk_split_best(line, self._delim)]

    def analyze(self, lines: list) -> None:
        """
        Detect delimiter and field structure from a sample of lines.
        Populates self.stat_fields.  Call before first use on a new file.
        """
        self._delim   = _unk_detect_delimiter(lines)
        sample_splits = [_unk_split(l, self._delim)
                         for l in lines if l.strip()][:50]

        if not sample_splits:
            self.stat_fields = []
            self._analyzed   = True
            return

        # Field count: 75th-percentile of observed counts, capped at 24.
        field_counts = sorted(len(s) for s in sample_splits)
        p75          = field_counts[max(0, int(len(field_counts) * 0.75) - 1)]
        n_fields     = min(p75, 24)

        ts_idx = self._find_ts_field(sample_splits)

        self.stat_fields = [
            PositionalField(
                idx   = i,
                label = 'Timestamp' if i == ts_idx else f'Field {i}',
                delim = self._delim,
                dtype = 'timestamp' if i == ts_idx else 'text',
            )
            for i in range(n_fields)
        ]
        self._analyzed = True

    def _find_ts_field(self, sample_splits: list) -> int | None:
        hits: Counter = Counter()
        for fields in sample_splits:
            for i, (val, _, _) in enumerate(fields):
                if isinstance(_extract_ts(val), datetime):
                    hits[i] += 1
                    break          # only count the first timestamp per line
        if not hits:
            return None
        best_idx, best_count = hits.most_common(1)[0]
        return best_idx if (best_count / len(sample_splits)) > 0.30 else None


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
    # Always available. Score returns 0
    types.append(UnknownLogType())
    return types


def auto_detect(path: str, lines: list, log_types: list) -> LogType:
    return max(log_types, key=lambda lt: lt.score(path, lines))


# Data layer

class LineStore:
    # All mutations should go through here. Enforces len(lines) == len(levels)
    def __init__(self, log_type: LogType):
        self._lines:       list = []
        self._lines_lower: list = []   # cached lower-case copy for literal search
        self._levels:      list = []
        self._lt                = log_type
    def __len__(self) -> int:
        return len(self._lines)

    def __getitem__(self, idx: int):
        return self._lines[idx], self._levels[idx]

    def get_line(self, idx: int) -> str:
        return self._lines[idx]

    def get_level(self, idx: int) -> str:
        return self._levels[idx]

    def append(self, line: str) -> None:
        # Append a line and automatically classify its level.
        self._lines.append(line)
        self._lines_lower.append(line.lower())
        self._levels.append(self._lt.detect_level(line))

    def bulk_load(self, lines: list, levels: list) -> None:
        assert len(lines) == len(levels)
        self._lines       = lines
        self._lines_lower = [l.lower() for l in lines]
        self._levels      = levels
    def replace_levels(self, new_levels: list) -> None:
        assert len(new_levels) == len(self._lines)
        self._levels = new_levels

    def set_log_type(self, lt: LogType) -> None:
        self._lt     = lt
        self._levels = [lt.detect_level(l) for l in self._lines]

    def trim_front(self, n: int) -> None:
        self._lines       = self._lines[n:]
        self._lines_lower = self._lines_lower[n:]
        self._levels      = self._levels[n:]
    def level_counts(self, indices=None) -> dict:
        src = self._levels if indices is None else [self._levels[i] for i in indices]
        c: dict = defaultdict(int)
        for lv in src:
            c[lv] += 1
        return dict(c)

    @property
    def log_type(self) -> LogType:
        return self._lt


class LogData:
    def __init__(self, path: str, log_type: LogType, display_name: str = ''):
        self.path         = path
        self.display_name = display_name or os.path.basename(path)
        self.log_type     = log_type
        self.store        = LineStore(log_type)
        self._file_pos    = 0

    def set_type(self, lt: LogType) -> None:
        self.log_type = lt
        self.store.set_log_type(lt)

    def load_async(self, progress_q: _queue.SimpleQueue) -> None:
        def _worker():
            CHUNK  = 4 * 1024 * 1024
            lines  = []
            levels = []
            lt     = self.log_type
            try:
                sz = os.path.getsize(self.path)
            except OSError:
                sz = 1
            try:
                with open(self.path, errors='replace') as fh:
                    buf = fh.buffer
                    while True:
                        chunk = fh.readlines(CHUNK)
                        if not chunk:
                            break
                        stripped = [l.rstrip('\n') for l in chunk]
                        lvls     = [lt.detect_level(l) for l in stripped]
                        lines.extend(stripped)
                        levels.extend(lvls)
                        pct = min(99, round(buf.tell() / max(1, sz) * 100))
                        progress_q.put(('progress', pct))
                self.store.bulk_load(lines, levels)
                self._file_pos = os.path.getsize(self.path)
            except Exception as e:
                self.store.bulk_load([f'[load error] {e}'], ['error'])
            progress_q.put(('done', None))

        threading.Thread(target=_worker, daemon=True, name='loader').start()

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
                self.store.append(l)
        self._file_pos = size
        return new

    def level_counts(self, indices=None) -> dict:
        return self.store.level_counts(indices)


# Docker integration

class _UnixHTTPConnection(http.client.HTTPConnection):
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
    HTTP/1.0 disables chunked transfer-encoding to force Docker to
    stream raw multiplexed frames with no chunk-size lines interleaved.
    """
    def __init__(self, container_id: str, q: _queue.SimpleQueue, tail: int = 500):
        self._id     = container_id
        self._q      = q
        self._tail   = tail
        self._stop   = threading.Event()
        self._sock   = None
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=f'docker-stream-{container_id[:8]}')

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        s = self._sock
        if s is not None:
            try:   s.close()
            except OSError: pass

    def _put(self, kind: str, payload) -> None:
        self._q.put((kind, payload))

    def _run(self) -> None:
        try:
            s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            s.connect(DOCKER_SOCKET)
            self._sock = s
        except OSError as exc:
            self._put('error', f'Cannot connect to Docker socket: {exc}')
            return

        path = (f'/containers/{self._id}/logs'
                f'?follow=1&stdout=1&stderr=1&tail={self._tail}')
        req  = (f'GET {path} HTTP/1.0\r\n'
                f'Host: localhost\r\n\r\n')
        try:
            s.sendall(req.encode())
        except OSError as exc:
            self._put('error', f'Docker log request failed: {exc}')
            return

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

        leftover = buf[buf.index(b'\r\n\r\n') + 4:]
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
        # Wait for a byte to decide framing mode
        if not _fill(1):
            self._put('eof', None)
            return

        if leftover[0] not in (1, 2):
            tty_mode = True

        while not self._stop.is_set():
            if tty_mode:
                if not _fill(1):
                    break
                newline_pos = leftover.find(b'\n')
                if newline_pos == -1:
                    if not _fill(len(leftover) + 1):
                        break
                    continue
                line     = leftover[:newline_pos].decode('utf-8', errors='replace')
                leftover = leftover[newline_pos + 1:]
                if line:
                    self._put('line', line)
            else:
                if not _fill(8):
                    break
                header   = leftover[:8]
                # stream_type = header[0]  — could distinguish stdout/stderr here
                length   = int.from_bytes(header[4:8], 'big')
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


class FIFOStreamer:
    """
    Bridges a named pipe to the ingest queue.

    A dedicated daemon thread owns the blocking open() and all subsequent
    reads, keeping the UI thread free. Stop by calling stop(); the write-end
    trick is necessary because readline() on a starved pipe blocks forever
    and cannot otherwise be interrupted from outside the thread.
    """
    def __init__(self, path: str, q: _queue.SimpleQueue):
        self._path   = path
        self._q      = q
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=f'fifo-stream-{os.path.basename(path)}')

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        """
        A pipe with no pending data blocks readline() indefinitely.
        Opening the write end forces an EOF on the read end, which
        unblocks the thread so it can check the stop flag and exit.
        """
        try:
            fd = os.open(self._path, os.O_WRONLY | os.O_NONBLOCK)
            os.close(fd)
        except OSError:
            pass  # pipe already closed; thread will exit on its own

    def _run(self) -> None:
        try:
            fd = os.open(self._path, os.O_RDONLY)   # blocks until writer ready
            with os.fdopen(fd, errors='replace') as fh:
                for raw in fh:
                    if self._stop.is_set():
                        break
                    line = raw.rstrip('\n')
                    if line:
                        self._q.put(('line', line))
        except OSError as exc:
            if not self._stop.is_set():
                self._q.put(('error', str(exc)))
        self._q.put(('eof', None))


# Stats / export helpers

STATS_WIDTH     = 44
_HBAR_W         = 20
_EXPORT_BAR_W   = 24
_EXPORT_VAL_W   = 32


def _bar(count: int, max_count: int, width: int = _HBAR_W, chars: str = '\u2588\u2591') -> str:
    if max_count == 0:
        return chars[1] * width
    filled = round(count / max_count * width)
    return chars[0] * filled + chars[1] * (width - filled)


def export_stats_to_text(stats, data, log_type, matched, filter_text,
                          level_filter, level_filter_inverted,
                          field_filters, field_filters_inverted,
                          text_filter_inverted) -> str:
    out      = []
    n_total  = len(data.store)
    n_shown  = len(matched)
    now      = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    out.append('LogAlyzer Stats Export')
    out.append('=' * 54)
    out.append(f'Generated : {now}')
    out.append(f'File      : {data.path}')
    out.append(f'Log type  : {log_type.name}')
    out.append(f'Lines     : {n_shown:,} shown of {n_total:,} total')
    if filter_text:
        inv = ' [INVERTED]' if text_filter_inverted else ''
        out.append(f'Filter    : {filter_text}{inv}')
    if level_filter:
        out.append(f'Levels    : {", ".join(sorted(level_filter))} (show only)')
    if level_filter_inverted:
        out.append(f'Levels    : {", ".join(sorted(level_filter_inverted))} (hidden)')
    for ft, vals in field_filters.items():
        label = next((f.label for f in log_type.stat_fields if f.type == ft), ft)
        inv = ' [INVERTED]' if any((ft, v) in field_filters_inverted for v in vals) else ''
        out.append(f'Field     : {label} = {", ".join(sorted(vals))}{inv}')
    out.append('')
    def section(title, rows):
        out.append(title); out.append('-' * len(title)); out.extend(rows); out.append('')
    hist = stats.get('histogram', [])
    if hist:
        max_v = max(c for _, c in hist)
        section('Activity over time', [
            f'  {l:>8}  {_bar(c, max_v, chars="#.")}  {c:>7,}' for l, c in hist])
    for label, kind, entries in stats.get('panels', []):
        if not entries: continue
        max_v = entries[0][1]
        section(label, [
            f'  {v[:_EXPORT_VAL_W]:<{_EXPORT_VAL_W}}  {_bar(c, max_v, chars="#.")}  {c:>7,}'
            for v, c in entries])
    if not hist and not stats.get('panels'):
        out.append('No stats available for the current view.'); out.append('')
    return '\n'.join(out)


# Status indicator

class StatusIndicator:
    _FRAMES = list('\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f')
    _BAR_W  = 12

    def __init__(self):
        self._mode  = 'idle'
        self._label = ''
        self._pct   = 0
        self._frame_idx = 0
        self._frame     = self._FRAMES[0]

    def set_idle(self):           self._mode = 'idle'
    def set_progress(self, l, p): self._mode, self._label, self._pct = 'progress', l, max(0,min(100,p))
    def set_spinner(self, l):     self._mode, self._label = 'spinner', l

    def tick(self) -> bool:
        self._frame_idx = (self._frame_idx + 1) % len(self._FRAMES)
        self._frame     = self._FRAMES[self._frame_idx]
        return self._mode == 'spinner'

    def render(self, tail_mode: bool) -> list:
        if self._mode == 'progress':
            filled = round(self._pct / 100 * self._BAR_W)
            bar    = '\u2593' * filled + '\u2591' * (self._BAR_W - filled)
            return [('h_dim', f' {self._label} [{bar}] {self._pct}%')]
        if self._mode == 'spinner':
            return [('h_dim', f' {self._frame} {self._label}\u2026')]
        if tail_mode:
            return [('tail_on', '\u25cf LIVE')]
        return [('tail_off', '\u25cb \u2500\u2500\u2500\u2500')]


# UI primitives

class EditField:
    def __init__(self):
        self.text:   str = ''
        self.cursor: int = 0

    def clear(self):
        self.text = ''; self.cursor = 0

    def handle_key(self, ch) -> bool:
        if ch == curses.KEY_LEFT:
            self.cursor = max(0, self.cursor - 1); return False
        if ch == curses.KEY_RIGHT:
            self.cursor = min(len(self.text), self.cursor + 1); return False
        if ch == curses.KEY_HOME:
            self.cursor = 0; return False
        if ch == curses.KEY_END:
            self.cursor = len(self.text); return False
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if self.cursor > 0:
                self.text = self.text[:self.cursor-1] + self.text[self.cursor:]
                self.cursor -= 1; return True
            return False
        if ch == curses.KEY_DC:
            if self.cursor < len(self.text):
                self.text = self.text[:self.cursor] + self.text[self.cursor+1:]
                return True
            return False
        if ch == 21:  # Ctrl-U
            if self.text:
                self.text = ''; self.cursor = 0; return True
            return False
        if 32 <= ch <= 126:
            c = chr(ch)
            self.text = self.text[:self.cursor] + c + self.text[self.cursor:]
            self.cursor += 1; return True
        return False

    def draw(self, stdscr, y, x, width, focused):
        a = _attr('fe_f') if focused else _attr('fe')
        vis_start = max(0, self.cursor - width + 1)
        vis = self.text[vis_start:vis_start + width].ljust(width)
        try: stdscr.addnstr(y, x, vis, width, a)
        except curses.error: pass
        if focused:
            cx = x + (self.cursor - vis_start)
            try: stdscr.move(y, min(cx, x + width - 1))
            except curses.error: pass


class LevelPillState:
    _DEFS = {
        'error': ('ERR',  'st_e', 'pill_e', 'pill_e_i'),
        'warn':  ('WARN', 'st_w', 'pill_w', 'pill_w_i'),
        'info':  ('INFO', 'st_i', 'pill_i', 'pill_i_i'),
        'debug': ('DBG',  'st_d', 'pill_d', 'pill_d_i'),
    }
    def __init__(self, key):
        self.level_key = key
        self._label, self._na, self._aa, self._ia = self._DEFS[key]
        self.count = 0; self.active = False; self.inverted = False

    def relabel(self, l):  self._label = l
    def reset(self):       self.active = self.inverted = False

    def toggle(self, invert=False):
        already = self.active and (self.inverted == invert)
        self.active   = not already
        self.inverted = invert if self.active else False

    def render_text(self):
        m = '\u2260' if self.active and self.inverted else '\u25b6' if self.active else ' '
        return f' {m}{self._label} {self.count:,} '

    def attr_name(self):
        if self.active and self.inverted: return self._ia
        if self.active: return self._aa
        return self._na


class FieldPillState:
    def __init__(self, ft, label, value, inverted=False):
        self.field_type = ft; self.label = label
        self.value = value; self.inverted = inverted

    def render_text(self):
        p = '\u2260' if self.inverted else '\u25b6'
        return f' {p}{self.label}:{self.value[:24]} \u00d7 '

    def attr_name(self):
        return 'fpill_inv' if self.inverted else 'fpill_n'


# Drawing helpers

class TogglePillState:
    def __init__(self, name: str, label: str, getter, setter):
        self.name    = name
        self.label   = label
        self._get    = getter
        self._set    = setter
    @property
    def state(self) -> bool:
        return self._get()
    def toggle(self) -> None:
        self._set(not self._get())
    def render_text(self) -> str:
        m = 'x' if self._get() else ' '
        return f' [{m}]{self.label} '
    def attr_name(self) -> str:
        return 'fpill_a' if self._get() else 'fpill_n'

def _safe(win, y, x, text, n, attr=0):
    try: win.addnstr(y, x, text, n, attr)
    except curses.error: pass

def draw_tokens(win, y, x, max_w, tokens, underline_spans=None):
    col, end = x, x + max_w
    for aname, text in tokens:
        if col >= end: break
        avail = end - col
        seg = text[:avail]
        seg_start = col; seg_end = col + len(seg)
        base = _attr(aname)
        if underline_spans and any(us < seg_end and ue > seg_start
                                    for us, ue in underline_spans):
            # Split this segment into contiguous underlined / non-underlined runs
            ul_attr = base | curses.A_UNDERLINE
            run_start = col
            while run_start < seg_end:
                # Find whether current position is underlined
                in_ul = any(us <= run_start < ue for us, ue in underline_spans)
                # Find end of this contiguous run (same underline state)
                run_end = seg_end
                for us, ue in underline_spans:
                    if in_ul:
                        if us <= run_start < ue: run_end = min(run_end, ue)
                    else:
                        if us > run_start:       run_end = min(run_end, us)
                chunk = seg[run_start - col:run_end - col]
                _safe(win, y, run_start, chunk, len(chunk),
                      ul_attr if in_ul else base)
                run_start = run_end
        else:
            _safe(win, y, col, seg, avail, base)
        col += len(seg)
    if col < end:
        _safe(win, y, col, ' ' * (end - col), end - col, _attr('ln'))

def draw_token_row(win, y, x, width, tokens, fill):
    col, end = x, x + width
    for aname, text in tokens:
        if col >= end: break
        avail = end - col
        _safe(win, y, col, text[:avail], avail, _attr(aname))
        col += len(text[:avail])
    if col < end:
        _safe(win, y, col, ' ' * (end - col), end - col, _attr(fill))


class _StreamSession:
    """Unified detection state for an active Docker or FIFO stream.

    Each call to _on_docker_selected / open_fifo creates a fresh instance
    with its own queue, so back-to-back container switches can never mix
    messages from an old streamer into the new session.
    """
    __slots__ = ('q', 'detected', 'detect_buf', 'hint', 'log_types', 'label')

    def __init__(self, q: _queue.SimpleQueue, hint: str,
                 log_types: list, label: str):
        self.q           = q
        self.detected    = False
        self.detect_buf: list = []
        self.hint        = hint        # path (FIFO) or image basename (Docker)
        self.log_types   = log_types
        self.label       = label       # shown in error messages: 'Docker' / 'FIFO'


# Main Application

class LogApp:
    HDR = 3   # title + filter + stats
    FTR = 1

    def __init__(self, data, log_types, detected):
        self.data = data; self.log_type = data.log_type
        self.log_types = log_types; self._detected = detected

        self.filter_text = ''; self.filter_re = None; self.filter_err = False
        self.use_regex = False; self.case_sens = False
        self.text_filter_inverted = False

        self.show_lineno = True; self.tail_mode = False; self.show_stats = False
        self.toggle_pills = [
            TogglePillState('regex', 'Rx', lambda: self.use_regex,   lambda v: setattr(self, 'use_regex',   v)),
            TogglePillState('case',  'Cs', lambda: self.case_sens,   lambda v: setattr(self, 'case_sens',   v)),
            TogglePillState('lno',   'Ln', lambda: self.show_lineno, lambda v: setattr(self, 'show_lineno', v)),
        ]
        self.viewport_off = 0; self.body_height = 0; self.body_width = 0

        self.level_filter: set = set()
        self.level_filter_inverted: set = set()
        self.pills = {k: LevelPillState(k) for k in ('error','warn','info','debug')}

        self.field_filters: dict = {}
        self.field_filters_inverted: set = set()
        self._pending: dict | None = None

        self.matched: list = []
        self.edit_field = EditField()
        self.focus = 'body'

        self.overlay = None; self.overlay_items = []; self.overlay_focus = 0
        self.overlay_scroll = 0; self.overlay_title = ''; self.overlay_on_select = None
        self.overlay_state = 'ready'; self.overlay_error = ''
        self._overlay_rect = (0, 0, 0, 0)
        self._pill_regions = []; self._field_pill_regions = []
        self.stats_scroll = 0; self.stats_focused = False; self._stats_pane_x = 0
        self._load_q = _queue.SimpleQueue(); self._stats_q = _queue.SimpleQueue()
        self._settype_q = _queue.SimpleQueue(); self._docker_fetch_q = _queue.SimpleQueue()
        self._stats_data = None

        self._streamer:       DockerStreamer | None  = None
        self._fifo_streamer:  FIFOStreamer   | None  = None
        self._stream_session: _StreamSession | None  = None

        self._status = StatusIndicator(); self._export_status = ''
        self._filter_deadline = None; self._last_spin_tick = 0.0

        self._pending_pill: tuple | None = None
        self.filter_submode = 'text'
        self.pill_focus_idx = 0
        self.running = True; self.dirty = True
        self._apply_filter()

    # Async loading

    def start_async_load(self):
        self._status.set_progress('Loading', 0)
        self.data.load_async(self._load_q)

    def _drain_load_q(self):
        changed = False
        while True:
            try: kind, payload = self._load_q.get_nowait()
            except _queue.Empty: break
            if kind == 'progress':
                self._status.set_progress('Loading', payload); changed = True
            elif kind == 'done':
                self._status.set_idle(); self._apply_filter(); changed = True
        if changed: self.dirty = True

    # Set log type

    def set_log_type(self, lt):
        self.log_type = lt
        self.field_filters.clear(); self.field_filters_inverted.clear()
        self._pending = None; self._pending_pill = None
        self.pill_focus_idx = 0; self.filter_submode = 'text'
        self._relabel_pills(lt)
        n      = min(100, len(self.data.store))
        sample = [self.data.store.get_line(i) for i in range(n)]
        lt.analyze(sample) # UnknownLogType
        self._status.set_spinner('Applying log type')
        def _w():
            nl = [lt.detect_level(self.data.store.get_line(i))
                  for i in range(len(self.data.store))]
            self._settype_q.put(nl)
        threading.Thread(target=_w, daemon=True, name='set-type').start()

    def _drain_settype_q(self):
        try: nl = self._settype_q.get_nowait()
        except _queue.Empty: return
        self.data.store.replace_levels(nl); self.data.log_type = self.log_type
        self._status.set_idle(); self._apply_filter(); self.dirty = True

    # Stats pane

    def _open_stats(self):
        self.show_stats = True; self._stats_data = None; self.stats_scroll = 0
        self._status.set_spinner('Computing stats')
        s, m, lt = self.data.store, list(self.matched), self.log_type
        def _w(): self._stats_q.put(compute_stats(s, m, log_type=lt))
        threading.Thread(target=_w, daemon=True, name='stats').start()

    def _drain_stats_q(self):
        try: self._stats_data = self._stats_q.get_nowait()
        except _queue.Empty: return
        self._status.set_idle(); self.dirty = True

    # Docker

    def open_docker_selector(self):
        self.overlay = 'docker'; self.overlay_state = 'loading'
        self.overlay_title = '\u25c9 LogAlyzer \u2014 Docker Containers'
        self.overlay_items = []; self.overlay_focus = 0
        self.overlay_scroll = 0; self.overlay_error = ''
        def _f():
            try: self._docker_fetch_q.put(('ok', docker_list_containers()))
            except Exception as e: self._docker_fetch_q.put(('error', str(e)))
        threading.Thread(target=_f, daemon=True, name='docker-fetch').start()

    def _drain_docker_fetch_q(self):
        try: kind, payload = self._docker_fetch_q.get_nowait()
        except _queue.Empty: return
        if kind == 'ok':
            self.overlay_state = 'ready'; self.overlay_items = payload
            if payload: self.overlay_focus = 0
        else:
            self.overlay_state = 'error'; self.overlay_error = payload
        self.dirty = True

    def _on_docker_selected(self, container):
        if self._streamer: self._streamer.stop(); self._streamer = None
        lts = load_log_types()
        pt = next((lt for lt in lts if lt.id == 'other'), lts[-1])
        disp = container['name'] or container['short_id']
        nd = LogData(f"docker://{container['id']}", pt, display_name=f"\u2692 {disp}")
        self.data = nd; self.log_type = pt; self.tail_mode = True
        hint = container['image'].split(':')[0].split('/')[-1]
        sq   = _queue.SimpleQueue()
        self._stream_session = _StreamSession(sq, hint, lts, 'Docker')
        self.field_filters.clear(); self.field_filters_inverted.clear()
        self._pending = None; self.matched = []; self._relabel_pills(pt)
        self._stats_data = None; self.show_stats = False; self.overlay = None
        self._streamer = DockerStreamer(container['id'], sq, tail=2000)
        self._streamer.start(); self.dirty = True

    def _drain_stream_q(self) -> None:
        sess  = self._stream_session
        batch = []
        while True:
            try: kind, payload = sess.q.get_nowait()
            except _queue.Empty: break
            if kind == 'line': batch.append(payload)
            elif kind == 'eof': self.tail_mode = False
            elif kind == 'error': self._export_status = f'\u26a0 {sess.label}: {payload}'
        if not batch: return
        if not sess.detected:
            sess.detect_buf.extend(batch)
            if len(sess.detect_buf) >= 20:
                det = auto_detect(sess.hint, sess.detect_buf, sess.log_types)
                sess.detected = True; self.log_type = det
                self.data.set_type(det); self._relabel_pills(det)
                batch = list(sess.detect_buf); sess.detect_buf = []
        self._ingest_streamed(batch)

    # FIFO streaming

    def open_fifo(self, path: str) -> None:
        if self._fifo_streamer:
            self._fifo_streamer.stop(); self._fifo_streamer = None
        pt = next((lt for lt in self.log_types if lt.id == 'other'), self.log_types[-1])
        disp = os.path.basename(path)
        nd = LogData(path, pt, display_name=f'\u22b3 {disp}')
        self.data = nd; self.log_type = pt; self.tail_mode = True
        sq   = _queue.SimpleQueue()
        self._stream_session = _StreamSession(sq, path, self.log_types, 'FIFO')
        self.field_filters.clear(); self.field_filters_inverted.clear()
        self._pending = None; self.matched = []; self._relabel_pills(pt)
        self._stats_data = None; self.show_stats = False
        self._fifo_streamer = FIFOStreamer(path, sq)
        self._fifo_streamer.start(); self.dirty = True

    def _ingest_streamed(self, lines: list) -> None:
        for l in lines: self.data.store.append(l)
        if len(self.data.store) > DOCKER_MAX_LINES:
            self.data.store.trim_front(len(self.data.store) - DOCKER_MAX_LINES)
        self._apply_filter()

    # Pills

    def _relabel_pills(self, lt):
        defs = {'error': 'ERR', 'warn': 'WARN', 'info': 'INFO', 'debug': 'DBG'}
        for k, p in self.pills.items(): p.relabel(lt.level_labels.get(k, defs[k]))

    def _refresh_pill_counts(self):
        ac = self.data.level_counts()
        for k, p in self.pills.items(): p.count = ac.get(k, 0)

    # Filter engine

    def _apply_filter(self):
        """
        Rebuild self.matched from lines passing all active filters (text, level, field).
        Updates pill counts, viewport, and dirty flag.
        """
        text = self.filter_text; store = self.data.store
        lf, lf_i = self.level_filter, self.level_filter_inverted
        ff, ff_i = self.field_filters, self.field_filters_inverted
        t_inv = self.text_filter_inverted

        pat = None
        if text:
            flags = 0 if self.case_sens else re.IGNORECASE
            try:
                pat = re.compile(text if self.use_regex else re.escape(text), flags)
                self.filter_re = pat; self.filter_err = False
            except re.error:
                self.filter_re = None; self.filter_err = True
        else:
            self.filter_re = None; self.filter_err = False

        # Short-circuit: no filters active, every line matches
        if not text and not lf and not lf_i and not ff:
            self.matched = list(range(len(store)))
            self._refresh_pill_counts()
            mx = max(0, len(self.matched) - max(1, self.body_height))
            self.viewport_off = min(self.viewport_off, mx)
            if self.tail_mode and self.matched: self.viewport_off = mx
            self.dirty = True
            return

        # Resolve field filters once outside the loop
        ff_fields = {}
        for ft, values in ff.items():
            f = next((f for f in self.log_type.stat_fields if f.type == ft), None)
            if f:
                inc = {v for v in values if (ft, v) not in ff_i}
                exc = {v for v in values if (ft, v) in ff_i}
                ff_fields[ft] = (f, inc, exc)

        text_active   = bool(text) and not self.filter_err
        use_literal   = text_active and not self.use_regex
        use_regex_pat = text_active and self.use_regex and pat is not None

        needle      = ''
        lines_lower = None
        if use_literal:
            if self.case_sens:
                needle = text
            else:
                needle      = text.lower()
                lines_lower = store._lines_lower

        # Main filter loop
        _lines  = store._lines
        _levels = store._levels
        matched = []
        append  = matched.append

        for i in range(len(_lines)):
            lvl = _levels[i]
            if lf   and lvl not in lf:  continue
            if lf_i and lvl in  lf_i:   continue

            if text_active:
                if use_literal:
                    if self.case_sens:
                        hit = needle in _lines[i]
                    else:
                        hit = needle in lines_lower[i]
                else:
                    hit = pat.search(_lines[i]) is not None
                if t_inv:
                    if hit:      continue
                else:
                    if not hit:  continue

            if ff_fields:
                line = _lines[i]
                ok   = True
                for ft, (f, inc, exc) in ff_fields.items():
                    val = f.extract(line)
                    if inc and val not in inc: ok = False; break
                    if exc and val in exc: ok = False; break
                if not ok: continue

            append(i)

        self.matched = matched; self._refresh_pill_counts()
        mx = max(0, len(matched) - max(1, self.body_height))
        self.viewport_off = min(self.viewport_off, mx)
        if self.tail_mode and matched: self.viewport_off = mx
        self.dirty = True

    def _schedule_filter(self):
        self._filter_deadline = time.monotonic() + 0.15

    # Click-to-filter

    def _hit_test(self, line, raw_col):
        for f in self.log_type.stat_fields:
            if not f.filterable: continue
            r = f.extract_with_span(line)
            if r is None: continue
            val, start, end = r
            if start <= raw_col < end:
                return {'field_type': f.type, 'label': f.label,
                        'value': val, 'start': start, 'end': end}
        return None

    def _set_pending(self, raw_idx, hit):
        self._pending = {**hit, 'raw_idx': raw_idx}; self.dirty = True

    def _cancel_pending(self):
        if self._pending is None: return
        self._pending = None; self.dirty = True

    def _confirm_pending(self):
        p = self._pending; ft = p['field_type']
        if ft not in self.field_filters: self.field_filters[ft] = set()
        self.field_filters[ft].add(p['value'])
        self._pending = None; self._apply_filter()

    # Pill keyboard-navigation helpers

    def _navigable_pills(self) -> list:
        # This must match the nav_idx increment order in _draw_statsbar exactly.
        level = list(self.pills.values())
        field = [pill for _, _, pill in self._field_pill_regions]
        return list(self.toggle_pills) + level + field
    def _clamp_pill_focus(self) -> None:
        pills = self._navigable_pills()
        if not pills:
            self.pill_focus_idx = 0
        else:
            self.pill_focus_idx = min(self.pill_focus_idx, len(pills) - 1)

    def _rebuild_level_filters(self) -> None:
        self.level_filter.clear()
        self.level_filter_inverted.clear()
        for p in self.pills.values():
            if p.active:
                (self.level_filter_inverted if p.inverted
                 else self.level_filter).add(p.level_key)

    def _set_pending_pill(self, pill) -> None:
        if isinstance(pill, TogglePillState):
            return
        key = (pill.field_type, pill.value) if isinstance(pill, FieldPillState) \
              else ('_level', pill.level_key)
        if self._pending_pill == key:
            self._remove_fpill(pill)
            self._pending_pill = None
            self._clamp_pill_focus()
        else:
            self._pending_pill = key
        self.dirty = True

    def _cancel_pending_pill(self) -> None:
        if self._pending_pill is None:
            return
        self._pending_pill = None
        self.dirty = True

    def _pill_is_pending(self, pill) -> bool:
        if self._pending_pill is None:
            return False
        if isinstance(pill, TogglePillState):
            return False
        key = (pill.field_type, pill.value) if isinstance(pill, FieldPillState) \
              else ('_level', pill.level_key)
        return self._pending_pill == key

    def toggle_tail(self):
        self.tail_mode = not self.tail_mode
        if self.tail_mode and self.matched:
            self.viewport_off = max(0, len(self.matched) - self.body_height)
        self.dirty = True

    def toggle_stats(self):
        if self.show_stats:
            self.show_stats = False; self._stats_data = None; self.stats_focused = False
        else:
            self._open_stats()
        self.dirty = True

    def clear_filter(self):
        self.level_filter.clear(); self.level_filter_inverted.clear()
        for p in self.pills.values(): p.reset()
        self.field_filters.clear(); self.field_filters_inverted.clear()
        self.text_filter_inverted = False; self._pending = None
        self._pending_pill = None; self.filter_submode = 'text'
        self.pill_focus_idx = 0
        self.edit_field.clear(); self.filter_text = ''; self.focus = 'body'
        self._apply_filter()

    def export_stats(self):
        stats = compute_stats(self.data.store, self.matched, log_type=self.log_type)
        text = export_stats_to_text(stats, self.data, self.log_type, self.matched,
            self.filter_text, self.level_filter, self.level_filter_inverted,
            self.field_filters, self.field_filters_inverted, self.text_filter_inverted)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        fname = f'logalyzer_stats_{ts}.txt'
        try:
            with open(os.path.join(os.getcwd(), fname), 'w') as fh: fh.write(text)
            self._export_status = f'exported -> {fname}'
        except OSError as e:
            self._export_status = f'export failed: {e}'
        self.dirty = True

    def open_logtype_selector(self):
        self._pre_selector_type = self.log_type
        self.overlay = 'logtype'
        self.overlay_title = '\u25c9 LogAlyzer \u2014 Select Log Type'
        self.overlay_state = 'ready'; items = []; fi = 0
        for i, lt in enumerate(self.log_types):
            suf = '  \u25c4 auto-detected' if lt is self._detected else ''
            items.append({'label': f' {lt.name}{suf}', 'data': lt})
            if lt is self._detected: fi = i
        self.overlay_items = items; self.overlay_focus = fi; self.overlay_scroll = 0
        self.overlay_on_select = lambda item: self.set_log_type(item['data'])
        self.dirty = True

    # Queue / timer drain

    def drain_queues(self):
        self._drain_load_q(); self._drain_settype_q(); self._drain_stats_q()
        self._drain_docker_fetch_q()
        if self._stream_session: self._drain_stream_q()

    def check_timers(self):
        now = time.monotonic()
        if self._filter_deadline and now >= self._filter_deadline:
            self._filter_deadline = None; self._apply_filter()
        if self._status._mode == 'spinner' and now - self._last_spin_tick >= 0.1:
            self._status.tick(); self._last_spin_tick = now; self.dirty = True

    # Input

    def on_key(self, ch):
        if self.overlay: self._overlay_key(ch); return
        if self.focus == 'filter':
            if ch == 27:
                self.filter_submode = 'text'
                self._cancel_pending_pill()
                self.clear_filter()

            elif ch == 9:  # Tab
                if self.filter_submode == 'text':
                    self.filter_submode = 'pills'
                    self._clamp_pill_focus()
                else:
                    self.filter_submode = 'text'
                    self._cancel_pending_pill()

            elif self.filter_submode == 'pills':
                pills = self._navigable_pills()

                if ch == curses.KEY_LEFT:
                    self.pill_focus_idx = max(0, self.pill_focus_idx - 1)
                    self._cancel_pending_pill()

                elif ch == curses.KEY_RIGHT:
                    self.pill_focus_idx = min(len(pills) - 1, self.pill_focus_idx + 1)
                    self._cancel_pending_pill()

                elif ch == ord(' ') and pills:
                    pill = pills[self.pill_focus_idx]
                    if isinstance(pill, TogglePillState):
                        self._cancel_pending_pill()
                        pill.toggle(); self._apply_filter()
                    elif isinstance(pill, LevelPillState):
                        self._cancel_pending_pill()
                        pill.toggle(invert=False)
                        self._rebuild_level_filters()
                        self._apply_filter()
                    else:
                        self._set_pending_pill(pill)

                elif ch in (curses.KEY_BACKSPACE, curses.KEY_DC, 127, 8) and pills:
                    pill = pills[self.pill_focus_idx]
                    self._cancel_pending_pill()
                    if isinstance(pill, TogglePillState):
                        pass
                    elif isinstance(pill, LevelPillState):
                        pill.reset()
                        self._rebuild_level_filters()
                        self._apply_filter()
                    else:
                        self._remove_fpill(pill)
                    self._clamp_pill_focus()

                elif ch == ord('i') and pills:
                    pill = pills[self.pill_focus_idx]
                    self._cancel_pending_pill()
                    if isinstance(pill, TogglePillState):
                        pass
                    elif isinstance(pill, LevelPillState):
                        pill.toggle(invert=True)
                        self._rebuild_level_filters()
                        self._apply_filter()
                    else:
                        self._invert_fpill(pill)

                elif ch == 10:  # Enter
                    self.filter_submode = 'text'
                    self._cancel_pending_pill()

            else:
                # filter_submode == 'text': keys go to the text field
                if ch == 10:
                    self.focus = 'body'
                    self.filter_submode = 'text'
                else:
                    if self.edit_field.handle_key(ch):
                        self.filter_text = self.edit_field.text
                        self._schedule_filter()

            self.dirty = True; return

        if ch in (ord('q'), ord('Q')): self.running = False
        elif ch == ord('/'): self.focus = 'filter'
        elif ch == 27:
            if self.stats_focused: self.stats_focused = False
            elif self._pending: self._cancel_pending()
            else: self.clear_filter()
        elif ch in (ord('t'), ord('T')): self.toggle_tail()
        elif ch in (ord('s'), ord('S')): self.toggle_stats()
        elif ch == ord('g'): self.viewport_off = 0
        elif ch == ord('G'): self.viewport_off = max(0, len(self.matched) - self.body_height)
        elif ch in (ord('e'), ord('E')): self.export_stats()
        elif ch in (ord('d'), ord('D')):
            if docker_available(): self.open_docker_selector()
        elif ch in (ord('l'), ord('L')):
            self.open_logtype_selector()
        elif ch == curses.KEY_LEFT:
            if self.show_stats:
                self.stats_focused = False
        elif ch == curses.KEY_RIGHT:
            if self.show_stats:
                self.stats_focused = True
        elif ch == curses.KEY_UP:
            if self.stats_focused:
                self.stats_scroll = max(0, self.stats_scroll - 1)
            else:
                self.viewport_off = max(0, self.viewport_off - 1)
        elif ch == curses.KEY_DOWN:
            if self.stats_focused:
                self.stats_scroll += 1
            else:
                self.viewport_off = min(max(0, len(self.matched) - self.body_height),
                                        self.viewport_off + 1)
        elif ch == curses.KEY_PPAGE:
            if self.stats_focused:
                self.stats_scroll = max(0, self.stats_scroll - self.body_height)
            else:
                self.viewport_off = max(0, self.viewport_off - self.body_height)
        elif ch == curses.KEY_NPAGE:
            if self.stats_focused:
                self.stats_scroll += self.body_height
            else:
                self.viewport_off = min(max(0, len(self.matched) - self.body_height),
                                        self.viewport_off + self.body_height)
        self.dirty = True

    def on_mouse(self, ev):
        try: _, mx, my, _, bstate = ev
        except (TypeError, ValueError): return

        b5 = getattr(curses, 'BUTTON5_PRESSED', 0x00200000)
        in_stats = self.show_stats and self._stats_pane_x > 0 and mx >= self._stats_pane_x
        if bstate & curses.BUTTON4_PRESSED:
            if self.overlay: self.overlay_scroll = max(0, self.overlay_scroll - 3)
            elif in_stats: self.stats_scroll = max(0, self.stats_scroll - 3)
            else: self.viewport_off = max(0, self.viewport_off - 3)
            self.dirty = True; return
        if bstate & b5:
            if self.overlay: self.overlay_scroll += 3
            elif in_stats: self.stats_scroll += 3
            elif self.matched:
                self.viewport_off = min(max(0, len(self.matched) - self.body_height),
                                        self.viewport_off + 3)
            self.dirty = True; return

        left  = bool(bstate & curses.BUTTON1_PRESSED)
        right = bool(bstate & curses.BUTTON3_PRESSED)
        if not left and not right: return

        if self.overlay: self._overlay_mouse(mx, my, bstate); return

        if my == 1 and left: self._handle_filter_click(mx)
        elif my == 2: self._handle_pill_click(mx, left, right)
        elif self.HDR <= my < self.HDR + self.body_height and left:
            if in_stats:
                self.stats_focused = True
            else:
                self.stats_focused = False
                self._cancel_pending_pill()
                self._handle_line_click(my, mx)
        self.dirty = True

    def _handle_filter_click(self, mx):
        self.focus = 'filter'
    def _handle_pill_click(self, mx, left, right):
        for xs, xe, name in self._cb_regions:
            if xs <= mx < xe:
                if name == 'regex': self.use_regex = not self.use_regex
                elif name == 'case': self.case_sens = not self.case_sens
                elif name == 'lno': self.show_lineno = not self.show_lineno
                self._apply_filter(); return
        self.focus = 'filter'

    def _handle_pill_click(self, mx, left, right):
        for xs, xe, pill in self._pill_regions:
            if xs <= mx < xe:
                self._cancel_pending_pill()
                if isinstance(pill, TogglePillState):
                    pill.toggle(); self._apply_filter()
                elif isinstance(pill, LevelPillState):
                    pill.toggle(invert=right)
                    self._rebuild_level_filters(); self._apply_filter()
                return
        for xs, xe, pill in self._field_pill_regions:
            if xs <= mx < xe:
                if left:
                    self._set_pending_pill(pill)
                elif right:
                    self._cancel_pending_pill()
                    self._invert_fpill(pill)
                return

    def _remove_fpill(self, pill):
        if pill.field_type == '_text_filter':
            self.text_filter_inverted = False
            self.edit_field.clear(); self.filter_text = ''; self._apply_filter(); return
        ft, val = pill.field_type, pill.value
        if ft in self.field_filters:
            self.field_filters[ft].discard(val)
            self.field_filters_inverted.discard((ft, val))
            if not self.field_filters[ft]: del self.field_filters[ft]
        self._apply_filter()

    def _invert_fpill(self, pill):
        if pill.field_type == '_text_filter':
            self.text_filter_inverted = not self.text_filter_inverted
        else:
            key = (pill.field_type, pill.value)
            if key in self.field_filters_inverted: self.field_filters_inverted.discard(key)
            else: self.field_filters_inverted.add(key)
        self._apply_filter()

    def _handle_line_click(self, sy, sx):
        log_w = self.body_width - 1
        if self.show_stats: log_w = self.body_width - STATS_WIDTH - 1
        if sx >= log_w: return
        mi = self.viewport_off + (sy - self.HDR)
        if mi >= len(self.matched): self._cancel_pending(); return
        raw = self.matched[mi]; line = self.data.store.get_line(raw)
        pw = len(f'{raw+1:6d} \u2502 ') if self.show_lineno else 0
        rc = sx - pw
        if rc < 0: self._cancel_pending(); return
        hit = self._hit_test(line, rc)
        if self._pending:
            p = self._pending
            if hit and hit['field_type'] == p['field_type'] and hit['value'] == p['value'] and raw == p['raw_idx']:
                self._confirm_pending(); return
            self._cancel_pending()
        if hit: self._set_pending(raw, hit)

    # Overlay key/mouse

    def _overlay_key(self, ch):
        if ch == 27:
            if self.overlay == 'logtype': self.set_log_type(getattr(self, '_pre_selector_type', self._detected))
            self.overlay = None; self.dirty = True; return
        if ch == curses.KEY_UP:
            self.overlay_focus = max(0, self.overlay_focus - 1); self.dirty = True; return
        if ch == curses.KEY_DOWN:
            self.overlay_focus = min(len(self.overlay_items) - 1, self.overlay_focus + 1)
            self.dirty = True; return
        if ch == 10:
            if self.overlay == 'docker' and self.overlay_state == 'ready':
                if self.overlay_items and self.overlay_focus < len(self.overlay_items):
                    self._on_docker_selected(self.overlay_items[self.overlay_focus])
            elif self.overlay == 'logtype':
                if self.overlay_items and self.overlay_focus < len(self.overlay_items):
                    cb = self.overlay_on_select; item = self.overlay_items[self.overlay_focus]
                    self.overlay = None
                    if cb: cb(item)
            self.dirty = True

    def _overlay_mouse(self, mx, my, bstate):
        if not (bstate & curses.BUTTON1_PRESSED): return
        top, lx, h, w = self._overlay_rect
        ry = my - top - 1
        if 0 <= ry < len(self.overlay_items) and lx < mx < lx + w - 1:
            self.overlay_focus = ry; self._overlay_key(10)
        self.dirty = True

    # Drawing

    def draw(self, stdscr):
        my, mx = stdscr.getmaxyx()
        if my < 5 or mx < 20: return
        self.body_height = my - self.HDR - self.FTR; self.body_width = mx

        stdscr.erase()
        self._draw_title(stdscr, mx)
        self._draw_filter(stdscr, mx)
        self._draw_statsbar(stdscr, mx)
        if self.focus == 'filter' and self.filter_submode == 'pills':
            self._clamp_pill_focus()
        bt = self.HDR
        if self.show_stats and mx > STATS_WIDTH + 10:
            lw = mx - STATS_WIDTH - 1
            self._stats_pane_x = lw + 1
            self._draw_body(stdscr, bt, self.body_height, 0, lw)
            self._draw_sb(stdscr, lw, bt, self.body_height)
            self._draw_statspane(stdscr, bt, lw + 1, STATS_WIDTH, self.body_height,
                                 self.stats_scroll)
        else:
            self._stats_pane_x = 0
            lw = mx - 1
            self._draw_body(stdscr, bt, self.body_height, 0, lw)
            self._draw_sb(stdscr, mx - 1, bt, self.body_height)

        self._draw_footer(stdscr, mx, my - 1)

        if self.focus == 'filter' and not self.overlay:
            curses.curs_set(1)
            ew = max(1, mx - 9)
            self.edit_field.draw(stdscr, 1, 9, ew, True)
        else:
            curses.curs_set(0)

        stdscr.noutrefresh()

        if self.overlay: self._draw_overlay(stdscr, my, mx)

    def _draw_title(self, s, mx):
        tok = [('header', ' \u25c9  LogAlyzer  '), ('h_dim', self.data.display_name),
               ('header', f'  [{self.log_type.name}]  ')] + self._status.render(self.tail_mode)
        draw_token_row(s, 0, 0, mx, tok, 'header')

    def _draw_filter(self, s, mx):
        _cb_defs = [('Regex','regex',self.use_regex),('Case','case',self.case_sens),('Ln','lno',self.show_lineno)]
        cbw = sum(len(f' [ ]{label} ') for label, _, _ in _cb_defs)
        ew = max(1, mx - 9)
        _safe(s, 1, 0, ' Filter: ', 9, _attr('fl'))
        if self.focus != 'filter': self.edit_field.draw(s, 1, 9, ew, False)
        tail = 9 + ew
        if tail < mx: _safe(s, 1, tail, ' ' * (mx - tail), mx - tail, _attr('fc'))
    def _draw_statsbar(self, s, mx):
        self._pill_regions = []; self._field_pill_regions = []; x = 0
        in_pill_mode = self.focus == 'filter' and self.filter_submode == 'pills'
        nav_idx = 0
        for tp in self.toggle_pills:
            is_focused = in_pill_mode and nav_idx == self.pill_focus_idx
            attr = 'hsel' if is_focused else tp.attr_name()
            t = tp.render_text(); sx = x
            _safe(s, 2, x, t, len(t), _attr(attr)); x += len(t)
            self._pill_regions.append((sx, x, tp))
            nav_idx += 1
        div = ' \u2502'
        _safe(s, 2, x, div, len(div), _attr('st')); x += len(div)
        for p in self.pills.values():
            is_focused = in_pill_mode and nav_idx == self.pill_focus_idx
            is_pending = self._pill_is_pending(p)
            attr = 'hsel' if (is_focused or is_pending) else p.attr_name()
            t = p.render_text(); sx = x
            _safe(s, 2, x, t, len(t), _attr(attr)); x += len(t)
            self._pill_regions.append((sx, x, p))
            nav_idx += 1
        div2 = '  \u2502'
        _safe(s, 2, x, div2, len(div2), _attr('st')); x += len(div2)
        if self.filter_err:
            e = ' \u26a0 bad regex '
            _safe(s, 2, x, e, len(e), _attr('ferr')); x += len(e)
        if self.filter_text and not self.filter_err:
            lb = 're' if self.use_regex else '~'
            fp = FieldPillState('_text_filter', lb, self.filter_text, self.text_filter_inverted)
            is_focused = in_pill_mode and nav_idx == self.pill_focus_idx
            is_pending = self._pill_is_pending(fp)
            attr = 'hsel' if (is_focused or is_pending) else fp.attr_name()
            t = fp.render_text(); sx = x
            _safe(s, 2, x, t, len(t), _attr(attr)); x += len(t)
            self._field_pill_regions.append((sx, x, fp))
            nav_idx += 1
        for ft, vals in self.field_filters.items():
            lb = next((f.label for f in self.log_type.stat_fields if f.type == ft), ft)
            for v in sorted(vals):
                inv = (ft, v) in self.field_filters_inverted
                fp = FieldPillState(ft, lb, v, inv)
                is_focused = in_pill_mode and nav_idx == self.pill_focus_idx
                is_pending = self._pill_is_pending(fp)
                attr = 'hsel' if (is_focused or is_pending) else fp.attr_name()
                t = fp.render_text(); sx = x
                _safe(s, 2, x, t, len(t), _attr(attr)); x += len(t)
                self._field_pill_regions.append((sx, x, fp))
                nav_idx += 1
        if self._pending:
            p = self._pending; t = f' \u25c8{p["label"]}:{p["value"][:24]} ? '
            _safe(s, 2, x, t, len(t), _attr('hsel')); x += len(t)
        tt = f' Total {len(self.data.store):,} '
        pad_start = max(x, mx - len(tt))
        if pad_start > x:
            _safe(s, 2, x, ' ' * (pad_start - x), pad_start - x, _attr('st'))
        _safe(s, 2, pad_start, tt, len(tt), _attr('st'))
    def _draw_body(self, s, ys, h, xs, w):
        for row in range(h):
            y = ys + row; idx = self.viewport_off + row
            if idx >= len(self.matched):
                _safe(s, y, xs, ' ' * w, w, _attr('ln')); continue
            raw = self.matched[idx]; line, lvl = self.data.store[raw]
            tok = self.log_type.make_markup(line, lvl, self.filter_re,
                                             raw + 1 if self.show_lineno else None)
            if self._pending and self._pending['raw_idx'] == raw:
                lw = len(f'{raw+1:6d} \u2502 ') if self.show_lineno else 0
                tok = _hl_span(tok, lw + self._pending['start'],
                               lw + self._pending['end'], 'hsel')
            ul_spans = self.log_type.filterable_spans(line)
            if ul_spans:
                lno_w = len(f'{raw+1:6d} \u2502 ') if self.show_lineno else 0
                ul_spans = [(xs + lno_w + cs, xs + lno_w + ce) for cs, ce in ul_spans]
            draw_tokens(s, y, xs, w, tok, ul_spans or None)

    def _draw_sb(self, s, x, ys, h):
        total = len(self.matched)
        if total <= h or h <= 0: tp = -1
        else:
            mo = max(1, total - h)
            tp = max(0, min(h - 1, round(self.viewport_off / mo * (h - 1))))
        for r in range(h):
            if r == tp:
                _safe(s, ys + r, x, '\u2503', 1, _attr('scrollbar_thumb'))
            else:
                _safe(s, ys + r, x, '\u2502', 1, _attr('scrollbar_trough'))

    def _draw_statspane(self, s, ys, xs, w, h, scroll: int = 0):
        visible = max(0, h - 2)
        rows = self._build_stats_rows(w)
        max_scroll = max(0, len(rows) - visible)
        scroll = min(scroll, max_scroll)
        self.stats_scroll = scroll

        border_attr = _attr('sp_hdr') if self.stats_focused else _attr('sp_border')
        _safe(s, ys, xs, '\u250c' + '\u2500' * (w - 2) + '\u2510', w, border_attr)
        title = ' Stats \u25bc' if self.stats_focused else ' Stats '
        tx = xs + max(1, (w - len(title)) // 2)
        _safe(s, ys, tx, title, len(title), _attr('sp_hdr'))

        if max_scroll > 0:
            thumb_row = round(scroll / max_scroll * (visible - 1))
        else:
            thumb_row = -1

        for i in range(1, h - 1):
            ri = (i - 1) + scroll
            _safe(s, ys + i, xs, '\u2502', 1, border_attr)
            sb_char = '\u2503' if (i - 1) == thumb_row and max_scroll > 0 else '\u2502'
            sb_attr = _attr('scrollbar_thumb') if (i - 1) == thumb_row and max_scroll > 0 \
                      else border_attr
            _safe(s, ys + i, xs + w - 1, sb_char, 1, sb_attr)
            if ri < len(rows):
                txt, an = rows[ri]
                _safe(s, ys + i, xs + 1, txt[:w-2].ljust(w - 2), w - 2, _attr(an))
            else:
                _safe(s, ys + i, xs + 1, ' ' * (w - 2), w - 2, _attr('sp_body'))
        if h > 1:
            _safe(s, ys + h - 1, xs, '\u2514' + '\u2500' * (w - 2) + '\u2518',
                  w, border_attr)

    def _build_stats_rows(self, w):
        stats = self._stats_data
        if stats is None: return [('Computing\u2026', 'sp_dim')]
        rows = []
        def sec(header, entries):
            if rows: rows.append(('\u2500' * (w - 2), 'sp_div'))
            rows.append((f' {header} ', 'sp_hdr')); rows.extend(entries)
        hist = stats.get('histogram', [])
        if hist:
            mv = max(c for _, c in hist)
            sec('Activity', [(f' {l:>6} {_bar(c, mv)} {c:>5}', 'sp_body') for l, c in hist])
        for label, kind, entries in stats.get('panels', []):
            if not entries: continue
            mv = entries[0][1]
            if kind == 'numeric':
                r = [(f' {v:<6} {_bar(c, mv, width=16)} {c:>5}', 'sp_body') for v, c in entries]
            else:
                vw = w - 20
                if any(len(v) > 16 for v, _ in entries):
                    r = []
                    for v, c in entries:
                        r.append((f' {_bar(c, mv, width=10)} {c:>4}', 'sp_body'))
                        r.append((f'  {v[:vw]}', 'sp_body'))
                else:
                    r = [(f' {v:<16} {_bar(c, mv, width=12)} {c:>5}', 'sp_body') for v, c in entries]
            sec(label, r)
        if not rows: rows.append(('  (no stats available)', 'sp_dim'))
        return rows

    def _draw_footer(self, s, mx, row):
        if self._pending:
            p = self._pending
            tok = [('fk','  Esc'),('footer',':cancel  '),('footer','  \u25c8 '),
                   ('fl',f'{p["label"]}: '),('hsel',f' {p["value"][:40]} '),
                   ('footer','  \u2190 click again to filter')]
            draw_token_row(s, row, 0, mx, tok, 'footer'); return

        if self._pending_pill:
            _, val = self._pending_pill
            tok = [('fk','  Space'),('footer',':confirm remove  '),
                   ('fk','Del'),    ('footer',':remove now  '),
                   ('fk','Esc'),    ('footer',':cancel  '),
                   ('footer', f'  \u25c8 pending: {str(val)[:40]}')]
            draw_token_row(s, row, 0, mx, tok, 'footer'); return

        if self.focus == 'filter' and self.filter_submode == 'pills':
            pills = self._navigable_pills()
            # clamp in case pill list shrank since last key event
            if self.pill_focus_idx >= len(pills):
                self.pill_focus_idx = max(0, len(pills) - 1)
            current = pills[self.pill_focus_idx] if pills else None
            if isinstance(current, LevelPillState):
                extra = [('fk','Space'),('footer',':toggle  ')]
            else:
                extra = [('fk','Space'),('footer',':select to remove  ')]
            tok = ([('fk','  \u2190\u2192'),('footer',':navigate  ')] +
                   extra +
                   [('fk','Del'),  ('footer',':remove  '),
                    ('fk','i'),    ('footer',':invert  '),
                    ('fk','Tab'),  ('footer',':back to search  '),
                    ('fk','Esc'),  ('footer',':exit')])
            draw_token_row(s, row, 0, mx, tok, 'footer'); return

        if self.focus == 'filter' and self.filter_submode == 'text':
            tok = [('fk','  Tab'),  ('footer',':navigate pills  '),
                   ('fk','Enter'), ('footer',':done  '),
                   ('fk','Esc'),   ('footer',':clear & exit')]
            draw_token_row(s, row, 0, mx, tok, 'footer'); return

        # Default footer
        n, m = len(self.data.store), len(self.matched)
        lf = f' (+{"+".join(sorted(self.level_filter))})' if self.level_filter else ''
        ff = ''
        if self.field_filters:
            parts = []
            for ft, vals in self.field_filters.items():
                lb = next((f.label for f in self.log_type.stat_fields if f.type == ft), ft)
                parts.append(f'{lb}:{"|".join(sorted(vals))}')
            ff = ' (' + ', '.join(parts) + ')'
        tok = [('fk','  q'),('footer',':quit  '),('fk','/'),('footer',':filter  '),
               ('fk','t'),('footer',':tail  '),('fk','s'),('footer',':stats  '),
               ('fk','e'),('footer',':export  '),('fk','d'),('footer',':docker  '),
               ('fk','l'),('footer',':logtype  '),
               ('fk','Esc'),('footer',':clear  '),('fk','g'),('footer','/'),
               ('fk','G'),('footer',':top/btm  '),
               ('footer','  click field to filter  R-click=invert  '),
               ('footer', f'{m:,}/{n:,} lines{lf}{ff}')]
        if self._export_status: tok.append(('footer', f'  {self._export_status}'))
        draw_token_row(s, row, 0, mx, tok, 'footer')

    def _draw_overlay(self, s, my, mx):
        if self.overlay == 'docker': self._draw_docker_ov(s, my, mx)
        elif self.overlay == 'logtype': self._draw_list_ov(s, my, mx)

    def _draw_list_ov(self, s, my, mx):
        items = self.overlay_items; n = len(items)
        w = min(mx - 4, 60); h = min(my - 4, n + 4)
        top = max(0, (my - h) // 2); lx = max(0, (mx - w) // 2)
        self._overlay_rect = (top, lx, h, w)
        try: win = curses.newwin(h, w, top, lx)
        except curses.error: return
        win.erase(); win.bkgd(' ', _attr('sel_box')); win.box()
        title = f' {self.overlay_title} '
        _safe(win, 0, max(1, (w - len(title))//2), title, w - 2, _attr('sel_box'))
        ih = h - 3
        for i in range(min(n, ih)):
            a = _attr('fc_f') if i == self.overlay_focus else _attr('fc')
            lb = items[i].get('label', str(items[i]))[:w-4]
            _safe(win, 1 + i, 1, lb.ljust(w - 2), w - 2, a)
        _safe(win, h - 2, 1, '\u2500' * (w - 2), w - 2, _attr('sp_div'))
        hint = ' \u2191\u2193 navigate  Enter select  Esc auto-detect '
        _safe(win, h - 1, 1, hint.center(w-2)[:w-2], w - 2, _attr('st'))
        win.noutrefresh()

    def _draw_docker_ov(self, s, my, mx):
        w = min(mx - 4, 70); items = self.overlay_items; st = self.overlay_state
        if st == 'loading':
            cl = [('\u25cc  Connecting to Docker\u2026', 'dk_spin')]
        elif st == 'error':
            cl = [(f'\u26a0  {self.overlay_error}', 'dk_err'),('','dk_dim'),
                  ('Is the Docker daemon running?','dk_dim')]
        else:
            if not items: cl = [('(no running containers found)','dk_dim')]
            else:
                cl = [(f' {"Container":<30} Image','dk_hdr'),('\u2500'*(w-2),'sp_div')]
                for ci, c in enumerate(items):
                    a = 'fc_f' if ci == self.overlay_focus else 'fc'
                    cl.append((f" {c['name']:<30} {c['image'][:28]}", a))
                    cl.append((f"   {c['short_id']}  {c['status']}", 'dk_dim'))
        h = min(my - 4, len(cl) + 4)
        top = max(0, (my - h)//2); lx = max(0, (mx - w)//2)
        self._overlay_rect = (top, lx, h, w)
        try: win = curses.newwin(h, w, top, lx)
        except curses.error: return
        win.erase(); win.bkgd(' ', _attr('dk_box')); win.box()
        title = f' {self.overlay_title} '
        _safe(win, 0, max(1,(w-len(title))//2), title, w-2, _attr('dk_box'))
        ih = h - 3
        for i in range(min(len(cl), ih)):
            t, an = cl[i]; _safe(win, 1+i, 1, t[:w-2].ljust(w-2), w-2, _attr(an))
        _safe(win, h-2, 1, '\u2500'*(w-2), w-2, _attr('sp_div'))
        hint = ' \u2191\u2193 navigate  Enter select  Esc cancel '
        _safe(win, h-1, 1, hint.center(w-2)[:w-2], w-2, _attr('st'))
        win.noutrefresh()



def main():
    ap = argparse.ArgumentParser(description='LogAlyzer \u2014 Terminal log analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('-f', '--file', metavar='PATH', help='Log file to open')
    src.add_argument('-d', '--docker', action='store_true',
                     help='Connect to Docker and select a container')
    src.add_argument('-F', '--fifo', metavar='PATH',
                     help='Read from a named pipe / FIFO (e.g. mkfifo journald)')
    args = ap.parse_args()

    if args.docker and not docker_available():
        sys.exit('Error: Docker socket not found at /var/run/docker.sock')

    if args.fifo:
        fifo_path = args.fifo
        try:
            st = os.stat(fifo_path)
        except OSError as e:
            sys.exit(f'Error: cannot stat {fifo_path!r}: {e}')
        if not stat.S_ISFIFO(st.st_mode):
            sys.exit(f'Error: {fifo_path!r} is not a named pipe. '
                     f'Create one with: mkfifo {fifo_path}')

    log_types = load_log_types()
    plain_type = next((lt for lt in log_types if lt.id == 'other'), log_types[-1])
    file_mode = bool(args.file); docker_mode = args.docker; fifo_mode = bool(args.fifo)

    if file_mode:
        path = args.file
        if not os.path.isfile(path): sys.exit(f'Error: {path!r} not found.')
        with open(path, errors='replace') as fh:
            preview = [fh.readline().rstrip('\n') for _ in range(50)]
        detected = auto_detect(path, preview, log_types)
        data = LogData(path, detected)
    elif fifo_mode:
        detected = plain_type
        data = LogData(args.fifo, plain_type,
                       display_name=f'\u22b3 {os.path.basename(args.fifo)}')
    else:
        detected = plain_type
        data = LogData('', plain_type, display_name='(connecting to Docker\u2026)')

    def run_curses(stdscr):
        init_colors('NO_COLOR' in os.environ)
        curses.curs_set(0)
        curses.mousemask(curses.ALL_MOUSE_EVENTS)
        curses.mouseinterval(0)
        stdscr.timeout(100); stdscr.keypad(True)

        app = LogApp(data, log_types, detected)
        if file_mode: app.open_logtype_selector(); app.start_async_load()
        elif fifo_mode: app.open_fifo(args.fifo)
        elif docker_mode: app.open_docker_selector()

        while app.running:
            app.drain_queues(); app.check_timers()
            if app.tail_mode and not app._stream_session and file_mode:
                new = app.data.poll_new()
                if new:
                    store = app.data.store; nb = len(store) - len(new)
                    for j, line in enumerate(new):
                        i = nb + j; lvl = store.get_level(i)
                        if app.level_filter and lvl not in app.level_filter: continue
                        if app.level_filter_inverted and lvl in app.level_filter_inverted: continue
                        if app.filter_re and not app.filter_re.search(line): continue
                        app.matched.append(i)
                    app._refresh_pill_counts()
                    if app.tail_mode:
                        app.viewport_off = max(0, len(app.matched) - app.body_height)
                    app.dirty = True

            ch = stdscr.getch()
            if ch == curses.KEY_RESIZE: app.dirty = True
            elif ch == curses.KEY_MOUSE:
                try: app.on_mouse(curses.getmouse())
                except curses.error: pass
            elif ch != -1: app.on_key(ch)

            if app.dirty:
                try: app.draw(stdscr); curses.doupdate()
                except curses.error: pass
                app.dirty = False

        if app._streamer: app._streamer.stop()
        if app._fifo_streamer: app._fifo_streamer.stop()

    os.environ.setdefault('ESCDELAY', '25')
    curses.wrapper(run_curses)


if __name__ == '__main__':
    main()
