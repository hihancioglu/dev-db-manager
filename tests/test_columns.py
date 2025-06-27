import json
from web.views import app

ALL_OPS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']


def test_columns_requires_login():
    client = app.test_client()
    resp = client.get('/api/columns?db=main::DB1&table=dbo.Users')
    assert resp.status_code == 403


def test_columns_permission(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'allow_query': True, 'main': {'DB2': ALL_OPS}}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'
    resp = client.get('/api/columns?db=main::DB1&table=dbo.Users')
    assert resp.status_code == 403


def test_columns_returns_list(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'allow_query': True, 'main': {'DB1': ALL_OPS}}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})

    executed_ip = []
    executed_sql = []
    cols = [('Id', 'int'), ('Name', 'nvarchar')]

    class FakeCursor:
        def execute(self, sql, *params):
            executed_sql.append(sql)
        def fetchall(self):
            return cols

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

    resp = client.get('/api/columns?db=main::DB1&table=dbo.Users')
    assert resp.status_code == 200
    data = json.loads(resp.data.decode('utf-8'))
    assert data['columns'] == [
        {'name': 'Id', 'type': 'int'},
        {'name': 'Name', 'type': 'nvarchar'}
    ]
    assert executed_ip == ['10.0.0.1']
    assert "USE [DB1]" in executed_sql[0]
