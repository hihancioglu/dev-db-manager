import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from web.views import run_backup_restore


def test_run_backup_restore_calls_masking(monkeypatch):
    calls = []
    monkeypatch.setattr('web.views.apply_data_masking', lambda db: calls.append(db))

    class FakeCursor:
        def __init__(self):
            self.call = []
            self.next_called = False
        def execute(self, sql, *args, **kwargs):
            self.call.append(sql)
        def fetchall(self):
            return [('logical', 'path', 'D'), ('log', 'path', 'L')]
        def nextset(self):
            return False
        def fetchone(self):
            return (1,)
    class FakeConn:
        def __init__(self, ip):
            self.cursor_obj = FakeCursor()
        def cursor(self):
            return self.cursor_obj
        def close(self):
            pass
        def commit(self):
            pass
    monkeypatch.setattr('web.views.get_conn', lambda ip: FakeConn(ip))

    run_backup_restore('ProdDB', 'DevDB', 'tester', '10.0.0.1')
    assert calls == ['DevDB']

