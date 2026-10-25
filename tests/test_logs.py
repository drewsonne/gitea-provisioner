import json
import logging
import sys

import pytest
from logs import JsonFormatter, configure_logging


def make_record(**extra):
    record = logging.LogRecord(
        "kopf.test", logging.INFO, __file__, 1, "hi %s", ("x",), None
    )
    record.__dict__.update(extra)
    return record


def test_record_is_one_line_with_workgraph_keys():
    line = JsonFormatter().format(make_record())
    assert "\n" not in line
    assert set(json.loads(line)) == {"time", "level", "logger", "message"}
    assert json.loads(line)["message"] == "hi x"
    assert json.loads(line)["level"] == "INFO"


def test_exc_with_exc_info():
    try:
        raise ValueError("boom")  # noqa: EM101, TRY301
    except ValueError:
        record = make_record()
        record.exc_info = sys.exc_info()
    assert "ValueError: boom" in json.loads(JsonFormatter().format(record))["exc"]


@pytest.mark.parametrize(
    ("ref", "expected"),
    [({"namespace": "gitea", "name": "bob"}, "gitea/bob"), ({"name": "bob"}, "bob")],
)
def test_object_from_k8s_ref(ref, expected):
    entry = json.loads(JsonFormatter().format(make_record(k8s_ref=ref)))
    assert entry["object"] == expected


def test_configure_logging_replaces_root_handlers():
    root = logging.getLogger()
    saved = root.handlers[:]
    try:
        root.addHandler(logging.NullHandler())
        configure_logging()
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)
    finally:
        root.handlers[:] = saved
