import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from web.views import app

def test_admin_shows_query_log(monkeypatch):
    monkeypatch.setattr('web.views.is_admin', lambda: True)
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {})
    monkeypatch.setattr('web.views.get_conn', lambda ip: (_ for _ in ()).throw(Exception()))
    monkeypatch.setattr('web.views.load_query_logs', lambda limit=100: [
        {'ts': '2024-01-01 12:00:00', 'user': 'tester', 'db': 'main/DB1', 'query': 'SELECT 1'}
    ])
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'
    resp = client.get('/admin')
    data = resp.data.decode('utf-8')
    assert 'SQL Sorgu Logu' in data
    assert 'SELECT 1' in data

