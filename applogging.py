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

APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(APP_DIR, "Logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")

MAX_BYTES = 10 * 1024 * 1024  # 10 MB per file
BACKUP_COUNT = 5  # 5 rotated backups → 60 MB cap total

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)-24s %(message)s"
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

    os.makedirs(LOG_DIR, exist_ok=True)

    root.setLevel(level)
    root.propagate = False  # don't leak to the python root logger

    # Remove any pre-existing handlers (e.g. from a previous import in tests)
    for h in list(root.handlers):
        root.removeHandler(h)

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
    """Parse a single log line into structured fields, or None if invalid."""
    line = line.rstrip("\r\n")
    if not line:
        return None
    # Format: "YYYY-MM-DD HH:MM:SS LEVEL    logger.name            message"
    parts = line.split(None, 3)
    if len(parts) < 4:
        return None
    date, time_, level, rest = parts
    level = level.strip().upper()
    if level not in _VALID_LEVELS:
        return None
    # Minimal date/time shape check so garbage lines don't parse
    if len(date) != 10 or date[4] != "-" or date[7] != "-":
        return None
    if len(time_) != 8 or time_[2] != ":" or time_[5] != ":":
        return None
    logger_name, _, message = rest.partition(" ")
    return {
        "timestamp": f"{date} {time_}",
        "level": level,
        "logger": logger_name.strip(),
        "message": message.strip(),
    }


# Configure on import so any module that imports this gets a ready logger
logger = configure()
