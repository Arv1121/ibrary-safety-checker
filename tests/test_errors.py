from unittest.mock import patch, MagicMock
from app import app


def make_response_json(data, status=200):
    mock = MagicMock()
    mock.status_code = status
    mock.json.return_value = data
    return mock


@patch('requests.post')
@patch('requests.get')
def test_search_handles_pypi_failure(get_mock, post_mock):
    # Simulate PyPI GET raising an exception
    import requests as _requests
    get_mock.side_effect = _requests.exceptions.RequestException('pypi down')

    # OSV returns no vulns
    post_mock.return_value = make_response_json({'vulns': []}, status=200)

    client = app.test_client()
    res = client.post('/search', data={'package': 'examplepkg', 'ecosystem': 'PyPI'})

    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert 'Notice:' in body
    assert 'Failed to fetch package metadata' in body


@patch('requests.post')
@patch('requests.get')
def test_search_handles_osv_failure(get_mock, post_mock):
    # PyPI returns normal metadata
    pypi_data = {'info': {'name': 'examplepkg', 'version': '1.2.3'}, 'releases': {}}
    get_mock.return_value = make_response_json(pypi_data, status=200)

    # OSV POST raises
    import requests as _requests
    post_mock.side_effect = _requests.exceptions.RequestException('osv down')

    client = app.test_client()
    res = client.post('/search', data={'package': 'examplepkg', 'ecosystem': 'PyPI'})

    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert 'Notice:' in body
    assert 'Failed to fetch vulnerability data' in body
