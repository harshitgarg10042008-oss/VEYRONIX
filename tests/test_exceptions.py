from datetime import datetime, timezone
from pathlib import Path

import pytest

from configsentinel.exceptions import ExceptionError, approve_exception, create_exception, load_exceptions, save_exception


FUTURE = "2099-01-01T00:00:00+00:00"


def test_exception_lifecycle_is_time_bound(tmp_path: Path):
    path = tmp_path / "exceptions.json"
    record = create_exception("ex-1", "finding-1", "alice", "maintenance window", FUTURE)
    assert record.status() == "PENDING"
    save_exception(record, path)
    approved = approve_exception("ex-1", "bob", path)
    assert approved.status() == "ACTIVE"
    assert approved.approved_by == "bob"
    assert load_exceptions(path)[0].as_dict()["verdict_impact"] == "none"


def test_expired_exception_cannot_be_created_or_approved(tmp_path: Path):
    with pytest.raises(ExceptionError):
        create_exception("ex-old", "f", "alice", "old", "2000-01-01T00:00:00+00:00")
    path = tmp_path / "exceptions.json"
    path.write_text('[{"exception_id":"ex-old","finding_id":"f","owner":"alice","justification":"old","expires_at":"2000-01-01T00:00:00+00:00"}]', encoding="utf-8")
    with pytest.raises(ExceptionError):
        approve_exception("ex-old", "bob", path)
