import json
from unittest.mock import patch, MagicMock
from app import app


def make_response_json(data, status=200):
    mock = MagicMock()
    mock.status_code = status
    mock.json.return_value = data
    return mock


def test_index_get():
    client = app.test_client()
    res = client.get('/')
    assert res.status_code == 200
    assert 'Open Source Library Safety Checker' in res.get_data(as_text=True)


@patch('requests.post')
@patch('requests.get')
def test_search_post_mocks(get_mock, post_mock):
    # Mock PyPI metadata response
    pypi_data = {
        'info': {'name': 'examplepkg', 'version': '1.2.3', 'license': 'MIT', 'summary': 'Example'},
        'releases': {}
    }
    get_mock.return_value = make_response_json(pypi_data, status=200)

    # Mock OSV response with one high severity vuln using CVSS_V3
    osv_data = {'vulns': [{'severity': [{'type': 'CVSS_V3', 'score': '8.5'}], 'id': 'OSV-123'}]}
    post_mock.return_value = make_response_json(osv_data, status=200)

    client = app.test_client()
    res = client.post('/search', data={'package': 'examplepkg', 'ecosystem': 'PyPI'})
    assert res.status_code == 200
    body = res.get_data(as_text=True)
    assert 'Verdict' in body
    assert 'Needs review' in body or 'High-severity' in body or 'vulns' in body
