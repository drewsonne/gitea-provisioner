"""One JSON object per log line, with the same keys as workgraph."""

from __future__ import annotations

import json
import logging


class JsonFormatter(logging.Formatter):
    """Format a record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        """Return the record as JSON with time, level, logger and message."""
        entry: dict[str, str] = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        ref = getattr(record, "k8s_ref", None)
        if ref:
            namespace = ref.get("namespace")
            name = ref.get("name")
            entry["object"] = f"{namespace}/{name}" if namespace else f"{name}"
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def configure_logging() -> None:
    """Send all logs, kopf's included, through one JSON handler."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logging.getLogger().handlers[:] = [handler]
