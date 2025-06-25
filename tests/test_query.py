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
