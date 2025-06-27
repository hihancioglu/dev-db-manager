import json
from web.views import app


def test_tables_requires_login():
    client = app.test_client()
    resp = client.get('/api/tables?db=main::DB1')
    assert resp.status_code == 403


def test_tables_permission(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'allow_query': True, 'main': ['DB2']}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'
    resp = client.get('/api/tables?db=main::DB1')
    assert resp.status_code == 403


def test_tables_returns_list(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'allow_query': True, 'main': ['DB1']}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})

    executed_ip = []
    executed_sql = []
    tables = [('dbo.Users',), ('dbo.Orders',)]

    class FakeCursor:
        def execute(self, sql):
            executed_sql.append(sql)
        def fetchall(self):
            return tables

    class FakeConn:
        def cursor(self):
            return FakeCursor()
        def close(self):
            pass

    def fake_get_conn(ip):
        executed_ip.append(ip)
        return FakeConn()

    monkeypatch.setattr('web.views.get_conn', fake_get_conn)

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'

    resp = client.get('/api/tables?db=main::DB1')
    assert resp.status_code == 200
    data = json.loads(resp.data.decode('utf-8'))
    assert data['tables'] == ['dbo.Users', 'dbo.Orders']
    assert executed_ip == ['10.0.0.1']
    assert "USE [DB1]" in executed_sql[0]

