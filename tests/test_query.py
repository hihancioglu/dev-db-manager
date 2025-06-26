import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from web.views import app, _detect_external_db


def test_detect_external_db():
    # same DB
    assert _detect_external_db('SELECT * FROM table', 'DB1') is None
    # use statement different
    assert _detect_external_db('USE OtherDB; SELECT 1', 'DB1') == 'OtherDB'
    # cross reference
    assert _detect_external_db('SELECT * FROM OtherDB.dbo.Table1', 'DB1') == 'OtherDB'
    # cross reference with brackets
    assert _detect_external_db('SELECT * FROM [OtherDB].dbo.Table1', 'DB1') == 'OtherDB'


def test_query_rejects_other_db(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'main': ['DB1']}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})

    def fake_get_conn(ip):
        raise AssertionError('get_conn should not be called')

    monkeypatch.setattr('web.views.get_conn', fake_get_conn)

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'

    resp = client.post('/query', data={'database': 'main::DB1', 'query': 'SELECT * FROM OtherDB.dbo.tbl'}, follow_redirects=True)
    assert b'farkli bir veritaban' in resp.data.lower()


def test_selected_db_in_response(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'main': ['DB1']}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})

    def fake_get_conn(ip):
        class FakeCursor:
            description = None

            def execute(self, *args, **kwargs):
                pass

            def fetchmany(self, *args, **kwargs):
                return []

            def close(self):
                pass

        class FakeConn:
            def cursor(self):
                return FakeCursor()

            def close(self):
                pass

        return FakeConn()

    monkeypatch.setattr('web.views.get_conn', fake_get_conn)

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'

    resp = client.post('/query', data={'database': 'main::DB1', 'query': 'SELECT 1'}, follow_redirects=True)
    html = resp.data.decode('utf-8')
    assert '<option value="main::DB1" selected>' in html


def test_update_shows_confirmation(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'main': ['DB1']}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})

    class FakeCursor:
        description = None

        def __init__(self):
            self.affected = 3

        def execute(self, sql, *args, **kwargs):
            pass

        def fetchone(self):
            return (self.affected,)

        def fetchmany(self, *args, **kwargs):
            return []

    class FakeConn:
        def cursor(self):
            return FakeCursor()

        def close(self):
            pass

    monkeypatch.setattr('web.views.get_conn', lambda ip: FakeConn())

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'

    resp = client.post('/query', data={'database': 'main::DB1', 'query': 'UPDATE t SET a=1'}, follow_redirects=True)
    assert b'id="confirmModal"' in resp.data
    with client.session_transaction() as sess:
        assert sess['pending_query'] == 'UPDATE t SET a=1'
        assert sess['pending_db'] == 'main::DB1'
        assert sess['affected'] == 3


def test_update_after_comment(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'main': ['DB1']}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})

    class FakeCursor:
        description = None

        def __init__(self):
            self.affected = 2

        def execute(self, sql, *args, **kwargs):
            pass

        def fetchone(self):
            return (self.affected,)

        def fetchmany(self, *args, **kwargs):
            return []

    class FakeConn:
        def cursor(self):
            return FakeCursor()

        def close(self):
            pass

    monkeypatch.setattr('web.views.get_conn', lambda ip: FakeConn())

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'

    query = "-- initial comment\nUPDATE t SET a=1"
    resp = client.post('/query', data={'database': 'main::DB1', 'query': query}, follow_redirects=True)
    assert b'id=\"confirmModal\"' in resp.data
    with client.session_transaction() as sess:
        assert sess['pending_query'] == query
        assert sess['pending_db'] == 'main::DB1'
        assert sess['affected'] == 2


def test_delete_after_declare(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'main': ['DB1']}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})

    class FakeCursor:
        description = None

        def __init__(self):
            self.affected = 1

        def execute(self, sql, *args, **kwargs):
            pass

        def fetchone(self):
            return (self.affected,)

        def fetchmany(self, *args, **kwargs):
            return []

    class FakeConn:
        def cursor(self):
            return FakeCursor()

        def close(self):
            pass

    monkeypatch.setattr('web.views.get_conn', lambda ip: FakeConn())

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'

    query = "DECLARE @x INT; DELETE FROM t"
    resp = client.post('/query', data={'database': 'main::DB1', 'query': query}, follow_redirects=True)
    assert b'id=\"confirmModal\"' in resp.data
    with client.session_transaction() as sess:
        assert sess['pending_query'] == query
        assert sess['pending_db'] == 'main::DB1'
        assert sess['affected'] == 1


def test_execute_query_uses_session(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'main': ['DB1']}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})

    executed = []

    class FakeCursor:
        description = None

        def execute(self, sql, *args, **kwargs):
            executed.append(sql)

        def fetchone(self):
            return (5,)

        def fetchmany(self, *args, **kwargs):
            return []

    class FakeConn:
        def cursor(self):
            return FakeCursor()

        def close(self):
            pass

    monkeypatch.setattr('web.views.get_conn', lambda ip: FakeConn())

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'
        sess['pending_query'] = 'UPDATE t SET a=1'
        sess['pending_db'] = 'main::DB1'
        sess['affected'] = 5

    resp = client.post('/execute-query', follow_redirects=True)
    html = resp.data.decode('utf-8')
    assert '<option value="main::DB1" selected>' in html
    assert 'UPDATE t SET a=1' in executed
    with client.session_transaction() as sess:
        assert 'pending_query' not in sess


def test_slack_called_on_update_execute(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'main': ['DB1']}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})

    slack = []

    class FakeCursor:
        description = None

        def execute(self, sql, *args, **kwargs):
            pass

        def fetchone(self):
            return (1,)

        def fetchmany(self, *args, **kwargs):
            return []

    class FakeConn:
        def cursor(self):
            return FakeCursor()

        def close(self):
            pass

    monkeypatch.setattr('web.views.get_conn', lambda ip: FakeConn())
    monkeypatch.setattr('web.views.send_slack_notification', lambda msg: slack.append(msg))

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'
        sess['pending_query'] = 'UPDATE t SET a=1'
        sess['pending_db'] = 'main::DB1'
        sess['affected'] = 1

    client.post('/execute-query', follow_redirects=True)
    assert slack
    assert 'UPDATE t SET a=1' in slack[0]


def test_slack_called_on_delete_execute(monkeypatch):
    monkeypatch.setattr('web.views.load_permissions', lambda: {'tester': {'main': ['DB1']}})
    monkeypatch.setattr('web.views.load_sql_servers', lambda: {'main': '10.0.0.1'})

    slack = []

    class FakeCursor:
        description = None

        def execute(self, sql, *args, **kwargs):
            pass

        def fetchone(self):
            return (2,)

        def fetchmany(self, *args, **kwargs):
            return []

    class FakeConn:
        def cursor(self):
            return FakeCursor()

        def close(self):
            pass

    monkeypatch.setattr('web.views.get_conn', lambda ip: FakeConn())
    monkeypatch.setattr('web.views.send_slack_notification', lambda msg: slack.append(msg))

    client = app.test_client()
    with client.session_transaction() as sess:
        sess['user'] = 'tester'
        sess['pending_query'] = 'DELETE FROM t'
        sess['pending_db'] = 'main::DB1'
        sess['affected'] = 2

    client.post('/execute-query', follow_redirects=True)
    assert slack
    assert 'DELETE FROM t' in slack[0]
