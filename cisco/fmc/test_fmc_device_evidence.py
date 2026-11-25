import json
from types import SimpleNamespace
import pytest
from cisco.fmc import device_evidence as module

SCOPE={'domain_id':'domain-one','device_id':'device-one'}


class FakeClient:
    instances=[]
    identity={'id':'device-one','metadata':{'domain':{'id':'domain-one'}}}
    partial=False
    def __init__(self, *args, **kwargs):
        assert kwargs=={'domain_uuid':'domain-one','verify':True}
        self.session=SimpleNamespace(close=lambda:None)
        self.endpoint_evidence={}
        self.calls=[]
        self.instances.append(self)
    def authenticate(self):self.calls.append('authenticate')
    def get_json(self,path):
        self.calls.append(path)
        return self.identity
    def get_all(self,path):
        self.calls.append(path)
        self.endpoint_evidence[path]={'status':'partial' if self.partial else 'complete','items_captured':1}
        return [{'id':'interface-one','name':'outside'}]


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setattr(FakeClient,'instances',[])
    monkeypatch.setattr(FakeClient,'partial',False)
    monkeypatch.setattr(FakeClient,'identity',{'id':'device-one','metadata':{'domain':{'id':'domain-one'}}})


def capture(tmp_path, **kwargs):
    return module.collect('fmc.example.invalid','synthetic-user','synthetic-secret',SCOPE,tmp_path,
        version='test',source_revision='a'*64,client_factory=FakeClient,**kwargs)


def test_scoped_collection_retains_json_receipts_and_never_claims_deployment(tmp_path):
    result=capture(tmp_path)
    assert result['complete'] and len(result['records'])==6
    assert all(row['scope']==SCOPE for row in result['records'])
    assert len(list(tmp_path.glob('*.native')))==6
    assert all('/devices/devicerecords/device-one' in path for path in FakeClient.instances[0].calls[1:])
    assert 'synthetic-secret' not in str(result)
    assert not any('deploy' in row['kind'] for row in result['records'])


@pytest.mark.parametrize('native', [
    {'id':'different-device','metadata':{'domain':{'id':'domain-one'}}},
    {'id':'device-one','metadata':{'domain':{'id':'different-domain'}}},
    {'id':'device-one'},
])
def test_identity_mismatch_or_missing_domain_stops_followup_requests(tmp_path, monkeypatch, native):
    monkeypatch.setattr(FakeClient,'identity',native)
    result=capture(tmp_path)
    assert not result['complete'] and len(result['records'])==1
    assert result['records'][0]['status'] in {'conflicting','not_interpreted'}
    assert len(FakeClient.instances[0].calls)==2


def test_partial_pages_retained_as_failed_and_only_failed_steps_retried(tmp_path,monkeypatch):
    monkeypatch.setattr(FakeClient,'partial',True)
    first=capture(tmp_path/'one')
    assert not first['complete']
    assert all(row['status']=='collection_failed' for row in first['records'][1:])
    native=json.loads((tmp_path/'one'/(first['records'][1]['id']+'.native')).read_bytes())
    assert len(native['items'])==1 and native['collection_evidence']['status']=='partial'
    monkeypatch.setattr(FakeClient,'partial',False)
    second=capture(tmp_path/'two',retry_records=first['records'])
    assert second['complete']
    third=capture(tmp_path/'three',retry_records=second['records'])
    assert third['complete'] and len(FakeClient.instances[-1].calls)==2


def test_cancel_retains_success_and_does_not_query_next_endpoint(tmp_path):
    rows=[]
    result=capture(tmp_path,on_progress=rows.append,cancelled=lambda:bool(rows))
    assert result['cancelled'] and len(result['records'])==1
    assert len(FakeClient.instances[0].calls)==2


def test_native_domain_link_verifies_exact_path_only():
    native={'id':'device-one','links':{'self':'https://fmc.example.invalid/api/fmc_config/v1/domain/domain-one/devices/devicerecords/device-one'}}
    assert module.native_identity(json.dumps(native).encode(),SCOPE)=='matching'
    native['links']['self'] += '/other'
    assert module.native_identity(json.dumps(native).encode(),SCOPE)=='conflicting'


def test_bounded_transport_forces_tls_and_refuses_device_writes(monkeypatch):
    import base64
    import requests
    seen=[]
    response=requests.Response();response.status_code=200
    response.iter_content=lambda size:iter([b'{}'])
    response.close=lambda:None
    def request(self,method,url,**kwargs):
        seen.append((method,url,kwargs));return response
    monkeypatch.setattr(requests.Session,'request',request)
    client=module.bounded_session(lambda:False)
    result=client.get('https://fmc.example.invalid/api/fmc_config/v1/domain/domain-one/devices/devicerecords/device-one',verify=False,allow_redirects=True)
    assert result.json()=={}
    assert seen[0][2]['verify'] is True and seen[0][2]['allow_redirects'] is False
    assert base64.b64decode(client.responses[0]['body_base64'])==b'{}'
    with pytest.raises(ValueError,match='Read-only'):
        client.post('https://fmc.example.invalid/api/deploy')
    assert len(seen)==1


def test_exact_response_envelope_refuses_changed_parsed_identity():
    import base64
    raw=b'{ "id": "device-one", "metadata": {"domain": {"id": "domain-one"}} }\r\n'
    envelope={'schema':'nc.fmc-api-responses.v1','data':json.loads(raw),
        'responses':[{'path':'/api/fmc_config/v1/domain/domain-one/devices/devicerecords/device-one',
                      'status':200,'body_base64':base64.b64encode(raw).decode()}]}
    assert module.native_identity(json.dumps(envelope).encode(),SCOPE)=='matching'
    envelope['data']['id']='changed'
    assert module.native_identity(json.dumps(envelope).encode(),SCOPE)=='conflicting'
