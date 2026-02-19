# LogAlyzer

Terminal UI log analyzer with mouse support.

## Requirements

- Python 3.10 or later
- urwid

```
pip install urwid
```

## Installation

```
git clone https://github.com/example/logalyzer.git
```

## Usage

```
python logalyzer.py <logfile>
```

## Log Types

Log type definitions are stored in `logtypes/*.json`. The program selects a type based on the filename and file contents. To add a type, copy an existing `.json` file and edit it.

Supported types out of the box:

| File | Type |
|------|------|
| nginx.json | Nginx Access Log |
| nginx-error.json | Nginx Error Log |
| syslog.json | Syslog / Journald |
| wine.json | Wine / Proton Debug Log |
| generic.json | Generic Application Log |

## Keys

| Key | Action |
|-----|--------|
| `/` | Focus filter bar |
| `Enter` | Return to log view |
| `Esc` | Clear filter, level pills, and field filters; return to log view |
| `t` | Toggle live tail |
| `s` | Toggle stats panel |
| `e` | Export current stats to file |
| `g` | Jump to top |
| `G` | Jump to bottom |
| `q` | Quit |

## Mouse

| Action | Result |
|--------|--------|
| Scroll wheel / Click scrollbar | Navigate the log |
| Click level pill | Toggle level filter |
| Click a field value | Select field filter (confirm with second click) |
| Left click on a field pill | Remove that filter |
| Right click on a field pill | Invert that filter |

## Stats Export

Press `e` to write a plain-text stats file to the current working directory. The filename is printed in the footer after export.
