# LogAlyzer

Terminal UI log analyzer with mouse support.

## Requirements

- Python 3.10 or later

## Installation

```
git clone https://github.com/calcanthum/logalyzer.git
```

## Usage

Log file:
```
python logalyzer.py -f <logfile>
```

Docker logs:
```
python logalyzer.py -d
```

FIFO logs:
```
python logalyzer.py -F <FIFO>
```
### Usage Examples

Nginx:
```
python logalyzer.py -f /var/log/nginx/access.log
```

Journald can write to a FIFO for logalyzer:
```
mkfifo /tmp/journal.pipe
journalctl -f -o short-iso > /tmp/journal.pipe & python3 logalyzer.py -F /tmp/journal.pipe
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
| `Esc` | Clear filter + level pills + field filters, return to log view |
| `t` | Toggle live tail |
| `s` | Toggle stats panel |
| `e` | Export current stats to file |
| `d` | Open Docker container selector |
| `g / G` | Jump to top / bottom |
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
