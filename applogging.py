"""applogging.py -- Centralized application logger for WinDesktopMgr.

Single source of truth for log configuration. All modules import `logger`
from here. Uses a RotatingFileHandler sized at 10 MB × 5 backups = 60 MB cap.

Logger hierarchy:
    windesktopmgr                -- root logger
    windesktopmgr.flask          -- HTTP request/response logs
    windesktopmgr.ps             -- PowerShell subprocess calls
    windesktopmgr.tray           -- tray state transitions
    windesktopmgr.remediation    -- remediation actions
    windesktopmgr.selftest       -- /api/selftest runs

Usage:
    from applogging import logger, get_logger
    logger.info("something happened")
    ps_log = get_logger("ps")
    ps_log.debug("ran: Get-WmiObject Win32_VideoController")
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys

APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(APP_DIR, "Logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")


def _is_running_under_pytest() -> bool:
    """Detect test runs so we never pollute the production log file."""
    return "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ


MAX_BYTES = 10 * 1024 * 1024  # 10 MB per file
BACKUP_COUNT = 5  # 5 rotated backups → 60 MB cap total

# Richer format: timestamp, level, thread name, logger, module:line, then the
# actual message. The thread name lets you see which parallel worker ran a PS
# call (useful for selftest's ThreadPoolExecutor). module:line lets you grep
# straight to the calling site.
LOG_FORMAT = (
    "%(asctime)s.%(msecs)03d %(levelname)-7s [%(threadName)-14s] %(name)-24s %(module)s:%(lineno)-4d %(message)s"
)
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def configure(level: int = logging.INFO) -> logging.Logger:
    """Configure the root windesktopmgr logger. Idempotent -- safe to call
    multiple times. Returns the root logger.
    """
    global _configured
    root = logging.getLogger("windesktopmgr")

    if _configured:
        return root

    root.setLevel(level)
    root.propagate = False  # don't leak to the python root logger

    # Remove any pre-existing handlers (e.g. from a previous import in tests)
    for h in list(root.handlers):
        root.removeHandler(h)

    # Under pytest: attach a NullHandler so messages are swallowed.
    # Production logs must never be polluted by mocked test subprocess calls.
    if _is_running_under_pytest():
        root.addHandler(logging.NullHandler())
        _configured = True
        return root

    os.makedirs(LOG_DIR, exist_ok=True)
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    root.addHandler(file_handler)

    _configured = True
    return root


def get_logger(suffix: str = "") -> logging.Logger:
    """Return a child logger under the windesktopmgr namespace."""
    if not _configured:
        configure()
    name = f"windesktopmgr.{suffix}" if suffix else "windesktopmgr"
    return logging.getLogger(name)


def read_recent(lines: int = 500, min_level: str | None = None) -> list[dict]:
    """Read the tail of the log file, optionally filtered by severity.

    Returns a list of parsed log entries (newest first):
        [{"timestamp": "...", "level": "INFO", "logger": "...", "message": "..."}]
    """
    if not os.path.exists(LOG_FILE):
        return []

    level_order = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
    min_rank = level_order.get((min_level or "").upper(), 0)

    # Read the last N*2 physical lines to account for filtering
    read_budget = max(lines * 4, 200)
    try:
        with open(LOG_FILE, encoding="utf-8", errors="replace") as f:
            raw = f.readlines()
    except OSError:
        return []

    raw = raw[-read_budget:]
    parsed: list[dict] = []

    for line in raw:
        entry = _parse_line(line)
        if entry is None:
            continue
        if level_order.get(entry["level"], 0) < min_rank:
            continue
        parsed.append(entry)

    parsed.reverse()  # newest first
    return parsed[:lines]


_VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def _parse_line(line: str) -> dict | None:
    """Parse a single log line into structured fields, or None if invalid.

    Supported formats:

        Legacy (pre-enrichment):
            YYYY-MM-DD HH:MM:SS LEVEL  logger.name    message

        Enriched (current):
            YYYY-MM-DD HH:MM:SS.mmm LEVEL [thread-name] logger.name module:line message
    """
    line = line.rstrip("\r\n")
    if not line:
        return None

    parts = line.split(None, 2)
    if len(parts) < 3:
        return None
    date, time_raw, rest = parts

    # Minimal date/time shape check so garbage lines don't parse
    if len(date) != 10 or date[4] != "-" or date[7] != "-":
        return None
    # time may be "HH:MM:SS" or "HH:MM:SS.mmm"
    time_base = time_raw.split(".")[0]
    if len(time_base) != 8 or time_base[2] != ":" or time_base[5] != ":":
        return None

    # Next token is the level
    level_parts = rest.split(None, 1)
    if len(level_parts) < 2:
        return None
    level = level_parts[0].strip().upper()
    if level not in _VALID_LEVELS:
        return None
    rest = level_parts[1]

    # Optional thread name block: "[thread-name] "
    thread = ""
    if rest.startswith("["):
        close = rest.find("]")
        if close != -1:
            thread = rest[1:close].strip()
            rest = rest[close + 1 :].lstrip()

    # Next token is the logger name
    logger_parts = rest.split(None, 1)
    if len(logger_parts) < 2:
        return None
    logger_name = logger_parts[0].strip()
    rest = logger_parts[1]

    # Optional module:line block (enriched format only)
    source = ""
    maybe_src, _, maybe_rest = rest.partition(" ")
    if ":" in maybe_src and not maybe_src.startswith("http"):
        # Looks like module:line
        mod, _, lineno = maybe_src.partition(":")
        if lineno.isdigit():
            source = maybe_src
            rest = maybe_rest

    return {
        "timestamp": f"{date} {time_raw}",
        "level": level,
        "thread": thread,
        "logger": logger_name,
        "source": source,
        "message": rest.strip(),
    }


# Configure on import so any module that imports this gets a ready logger
logger = configure()
