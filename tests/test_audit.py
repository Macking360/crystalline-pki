import sqlite3
import threading
from contextlib import closing


def test_chain_is_valid_and_grows(app):
    for number in range(5):
        app.audit.record("event %d" % number)
    result = app.audit.verify_chain()
    assert result["valid"]
    assert result["records_checked"] >= 5


def test_tampering_is_detected(app):
    for number in range(4):
        app.audit.record("event %d" % number)
    with closing(sqlite3.connect(str(app.workspace.database))) as db:
        db.execute("UPDATE events SET action='forged' WHERE id=2")
        db.commit()
    result = app.audit.verify_chain()
    assert not result["valid"]
    assert any("mismatch" in f["problem"] for f in result["failures"])


def test_deletion_is_detected(app):
    for number in range(4):
        app.audit.record("event %d" % number)
    with closing(sqlite3.connect(str(app.workspace.database))) as db:
        db.execute("DELETE FROM events WHERE id=3")
        db.commit()
    assert not app.audit.verify_chain()["valid"]


def test_expected_head_catches_truncation(app):
    app.audit.record("one")
    anchor = app.audit.head_hash()
    app.audit.record("two")
    assert app.audit.verify_chain(expect_head=app.audit.head_hash())["valid"]
    assert not app.audit.verify_chain(expect_head=anchor)["valid"]


def test_concurrent_writers_do_not_fork_the_chain(app):
    def writer(prefix):
        for number in range(15):
            app.audit.record("%s-%d" % (prefix, number))

    threads = [threading.Thread(target=writer, args=(str(i),)) for i in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    result = app.audit.verify_chain()
    assert result["valid"]
    assert result["records_checked"] >= 75
