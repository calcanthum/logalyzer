# LogAlyzer

Terminal log viewer with filtering, stats, live tail, and mouse support. No dependencies beyond Python 3.10+.

```
python logalyzer.py -f <logfile>
python logalyzer.py -d              # Docker container selector
python logalyzer.py -F <fifo>       # Named pipe
```

Journald example:

```sh
mkfifo /tmp/journal.pipe
journalctl -f -o short-iso > /tmp/journal.pipe &
python3 logalyzer.py -F /tmp/journal.pipe
```

## Log Types

Detected automatically from filename and file contents. Press `l` to switch manually.

| File | Type |
|------|------|
| `nginx.json` | Nginx access log |
| `nginx-error.json` | Nginx error log |
| `syslog.json` | Syslog / journald |
| `mariadb.json` | MariaDB / MySQL error log |
| `wine.json` | Wine / Proton debug log |
| `generic.json` | Generic application log |

To add a type, copy an existing JSON file and edit it.

## Keys

| Key | Action |
|-----|--------|
| `/` | Open filter bar |
| `Tab` | (in filter bar) Switch between text field and filter pills |
| `Enter` | Return to log view |
| `Esc` | Clear all filters |
| `t` | Toggle live tail |
| `s` | Toggle stats panel |
| `←` / `→` | Move focus between log and stats panel |
| `e` | Export stats to file |
| `d` | Docker container selector |
| `l` | Log type selector |
| `g` / `G` | Top / bottom |
| `q` | Quit |

## Mouse

| Action | Result |
|--------|--------|
| Scroll wheel | Navigate the log |
| Click level pill | Toggle level filter |
| Click a field value | Select field filter (apply with second click) |
| Left click on a field pill | Remove that filter |
| Right click on a field pill | Invert that filter |

## Filtering

**Text:** Press `/` and type. Toggle Regex and Case checkboxes at the right of the filter bar.

**Level pills:** Click a level pill to show only that level. Right-click to exclude it.

**Field filters:** Filterable values (IPs, paths, hostnames, etc.) are underlined in the log view. Click a value to create a pending filter (it will appear in the stats bar). Click the same value again to apply it. Right-click a pill to invert it.

In keyboard mode (`Tab` from the filter bar): `←` / `→` navigate pills, `Space` toggles, `i` inverts, `Del` removes.

All active filters combine with AND.

## Stats Panel

Shows an activity histogram and top values for filterable fields, computed from the current view. Press `e` to export to a plain-text file in the working directory.

## Log Type JSON Format

```json
{
  "id": "my_log",
  "name": "My Log Format",
  "detect": {
    "filename_keywords": ["myapp"],
    "content_regex": "^\\d{4}-\\d{2}-\\d{2}"
  },
  "fields": [...],
  "level_rules": [...],
  "highlights": [...]
}
```

**`detect`** — `filename_keywords` matched against the filename; `content_regex` tested against the first 20 lines. Highest score wins.

**`level_rules`** — classify each line. First match wins.

```json
{"regex": "\\b(ERROR|ERR)\\b", "level": "error", "flags": "i"}
```

Levels: `error`, `warn`, `info`, `debug`.

**`highlights`** — apply color to matched spans. Only recolors spans still at their base attribute.

```json
{"regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", "attr": "hip"}
```

`attr` values: `he` (error), `hw` (warn), `hi` (info), `hd` (debug), `hip` (IP), `h2ok`, `h3xx`, `h4xx`, `lno` (dim).

**`fields`** — what to extract for stats and filtering.

```json
{
  "type": "ip",
  "label": "IP",
  "dtype": "text",
  "regex": "\\b((?:\\d{1,3}\\.){3}\\d{1,3})\\b",
  "multi": true,
  "filterable": true
}
```

| Key | Notes |
|-----|-------|
| `dtype` | `timestamp`, `text`, `numeric`, `compound` |
| `multi` | Extract all matches per line, not just the first |
| `filterable` | Underlines the value in the log view; click to filter |
| `normalize` | Replaces numeric/UUID path segments with `{id}` |
| `error_levels` | Only extract for lines at these levels |
| `group` | Regex capture group (default: 1) |
| `buckets` | For `numeric`: map value ranges to labels |
| `components` + `format` | For `compound`: combine fields, e.g. `"{http_method} {http_path}"` |

**`level_labels`** — override pill display names, e.g. `"error": "5xx"`.

## Screenshots
<div align="center">
  <img alt="screenshot" src="https://github.com/user-attachments/assets/df2284e0-95d2-4e7f-91c1-7db9668ae6a7" width="30%"/>
  <img alt="screenshot2" src="https://github.com/user-attachments/assets/613af3cd-c765-4353-a78a-372709ee89dc" width="30%"/>
  <img alt="screenshot3" src="https://github.com/user-attachments/assets/93534295-33ac-458a-b68b-7a28b6c4da4a" width="30%"/>
</div>
