"""Wall clock and sleep. Tests replace these."""

import time
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc)


def sleep(seconds):
    if seconds > 0:
        time.sleep(seconds)
