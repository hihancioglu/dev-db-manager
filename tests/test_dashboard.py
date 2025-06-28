import os, sys, json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from web.views import app


def test_active_job_progress_element(monkeypatch):
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {})
    monkeypatch.setattr('web.views.load_permissions', lambda: {})
    monkeypatch.setattr('web.views.is_admin', lambda: False)
    monkeypatch.setattr('web.views.get_conn', lambda ip: (_ for _ in ()).throw(Exception()))
    monkeypatch.setattr('web.views.active_job', {'prod_db': 'BMS', 'dev_db': 'main_BMS_tester', 'username': 'tester'})
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'
    resp = client.get('/dashboard')
    html = resp.data.decode('utf-8')
    assert 'id="active-job-status"' in html
    assert 'progress?dev_db=main_BMS_tester' in html


def test_dashboard_shows_cancel_for_queued_job(monkeypatch):
    from collections import deque
    q = deque([
        {'prod_db': 'BMS', 'dev_db': 'main_BMS_tester', 'username': 'tester'},
        {'prod_db': 'BMS2', 'dev_db': 'main_BMS2_other', 'username': 'other'},
    ])
    monkeypatch.setattr('web.views.job_queue', q)
    monkeypatch.setattr('web.views.active_job', {'dummy': True})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {})
    monkeypatch.setattr('web.views.load_permissions', lambda: {})
    monkeypatch.setattr('web.views.is_admin', lambda: False)
    monkeypatch.setattr('web.views.get_conn', lambda ip: (_ for _ in ()).throw(Exception()))

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'
    resp = client.get('/dashboard')
    html = resp.data.decode('utf-8')
    assert html.count('action="/cancel-queued"') == 1


def test_cancel_queued_removes_job(monkeypatch):
    from collections import deque
    q = deque([
        {'prod_db': 'BMS', 'dev_db': 'main_BMS_tester', 'username': 'tester'}
    ])
    monkeypatch.setattr('web.views.job_queue', q)
    monkeypatch.setattr('web.views.active_job', {'dummy': True})

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'

    client.post('/cancel-queued', data={'dev_db': 'main_BMS_tester'})

    assert len(q) == 0

