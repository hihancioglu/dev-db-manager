import os
import sys
import json
import logging
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from web.views import app, log_query, log_action

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


def test_log_query_emits_syslog(monkeypatch):
    messages = []

    class DummyHandler(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    dummy_logger = logging.getLogger("dummy")
    dummy_logger.setLevel(logging.INFO)
    dummy_logger.addHandler(DummyHandler())

    monkeypatch.setattr('web.views.query_logger', dummy_logger)

    log_query('tester', 'main/DB1', 'SELECT 1')

    assert len(messages) == 1
    data = json.loads(messages[0])
    assert data['user'] == 'tester'
    assert data['database'] == 'main/DB1'
    assert data['query'] == 'SELECT 1'


def test_log_action_emits_syslog(monkeypatch):
    messages = []

    class DummyHandler(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    dummy_logger = logging.getLogger("dummy_action")
    dummy_logger.setLevel(logging.INFO)
    dummy_logger.addHandler(DummyHandler())

    monkeypatch.setattr('web.views.query_logger', dummy_logger)

    log_action('tester', 'create_dev_db', prod_db='BMS', dev_db='main_BMS_tester')

    assert len(messages) == 1
    data = json.loads(messages[0])
    assert data['user'] == 'tester'
    assert data['action'] == 'create_dev_db'
    assert data['dev_db'] == 'main_BMS_tester'


def test_update_permissions_keep_allow_query(monkeypatch):
    perms = {'user1': {'allow_query': False, 'main': {'DB1': ['SELECT']}}}
    saved = {}
    monkeypatch.setattr('web.views.is_admin', lambda: True)
    monkeypatch.setattr('web.views.load_permissions', lambda: json.loads(json.dumps(perms)))
    monkeypatch.setattr('web.views.save_permissions', lambda p: saved.update(p))

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'admin'

    client.post('/admin/update-permissions', data={'user': 'user1', 'db-user1-main::DB1': 'on'})

    assert saved['user1']['allow_query'] is False


def test_update_permissions_preserves_ops(monkeypatch):
    perms = {'user1': {'allow_query': True, 'main': {'DB1': ['SELECT', 'INSERT']}}}
    saved = {}
    monkeypatch.setattr('web.views.is_admin', lambda: True)
    monkeypatch.setattr('web.views.load_permissions', lambda: json.loads(json.dumps(perms)))
    monkeypatch.setattr('web.views.save_permissions', lambda p: saved.update(p))

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'admin'

    client.post('/admin/update-permissions', data={'user': 'user1', 'db-user1-main::DB1': 'on'})

    assert saved['user1']['main']['DB1'] == ['SELECT', 'INSERT']

