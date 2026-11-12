import logging
import os
import re
from pathlib import Path
from datetime import datetime

class RedactingFormatter(logging.Formatter):
    """
    Format logs while automatically redacting passwords, session tokens, and credentials.
    """
    SENSITIVE_PATTERNS = [
        re.compile(r'(password["\']?\s*[:=]\s*["\']?)([^"\'&\s]+)', re.IGNORECASE),
        re.compile(r'(_sessionTOKEN["\']?\s*[:=]\s*["\']?)([^"\'&\s]+)', re.IGNORECASE),
        re.compile(r'(SID_HTTPS_["\']?\s*[:=]\s*["\']?)([^"\'&\s;]+)', re.IGNORECASE),
        re.compile(r'(sessToken["\']?\s*[:=]\s*["\']?)([^"\'&\s]+)', re.IGNORECASE),
    ]

    @classmethod
    def add_secret(cls, secret):
        if secret and len(secret) >= 4:
            cls.SENSITIVE_PATTERNS.append(re.compile(re.escape(secret), re.IGNORECASE))

    def format(self, record):
        msg = super().format(record)
        for pattern in self.SENSITIVE_PATTERNS:
            msg = pattern.sub(r'\1[REDACTED]' if pattern.groups > 1 else '[REDACTED]', msg)
        return msg

def setup_logger(name="zte_toolkit", log_dir=None, verbose=False):
    if log_dir is None:
        log_dir = Path(__file__).resolve().parents[1] / "logs"
    else:
        log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    formatter = RedactingFormatter(
        fmt="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler
    log_file = log_dir / f"zte_toolkit_{datetime.now():%Y%m%d}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger

