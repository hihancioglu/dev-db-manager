import json
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from web.views import app, active_jobs


def test_progress_reports_running(monkeypatch):
    dev_db = 'main_DB1_tester'
    job_info = {
        'stage': 'backup',
        'percent': 0,
        'prod_db': 'DB1',
        'source_sql': '10.0.0.2',
    }
    monkeypatch.setitem(active_jobs, dev_db, job_info)

    def fake_get_conn(ip):
        class FakeCursor:
            def execute(self, sql, *params):
                pass
            def fetchall(self):
                if ip == '10.0.0.2':
                    Row = type('Row', (), {
                        'percent_complete': 12,
                        'command': 'BACKUP DATABASE',
                        'sql_text': 'BACKUP DATABASE DB1'
                    })
                    return [Row()]
                return []
        class FakeConn:
            def cursor(self):
                return FakeCursor()
            def close(self):
                pass
        return FakeConn()

    monkeypatch.setattr('web.views.get_conn', fake_get_conn)

    client = app.test_client()
    resp = client.get('/progress?dev_db=' + dev_db)
    data = json.loads(resp.data.decode('utf-8'))
    assert data['stage'] == 'backup'
    assert data['status'] == 'running'
