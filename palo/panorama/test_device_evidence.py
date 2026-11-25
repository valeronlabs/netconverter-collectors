import sys
import pytest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from device_evidence import collect

SERIAL="000000000001"

class Response:
    status_code=200
    def __init__(self,raw): self.raw=raw
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def iter_content(self,*args): yield self.raw

class Client:
    def __init__(self,responses): self.responses=iter(responses);self.calls=[]
    def post(self,url,**kwargs):
        self.calls.append((url,kwargs));return Response(next(self.responses))

def identity(serial=SERIAL):
    return ('<response status="success"><result><system><serial>'+serial+'</serial></system></result></response>').encode()

def run(tmp_path,client,**kwargs):
    return collect('panorama.example.invalid','synthetic-key',SERIAL,tmp_path,
                   version='test',source_revision='a'*64,session=client,**kwargs)

def test_selected_capture_is_read_only_tls_bound_and_retains_each_response(tmp_path):
    client=Client([identity()]+[b'<response status="success"><result><config/></result></response>']*3)
    result=run(tmp_path,client)
    assert result['complete'] and len(list(tmp_path.glob('*.native')))==4
    for url,call in client.calls:
        assert 'synthetic-key' not in url
        assert call['verify'] is True and call['allow_redirects'] is False
        assert call['data']['type']=='op' and call['data']['target']==SERIAL
        assert call['data']['cmd'].startswith('<show>')
    assert all(not row['complete'] for row in result['records'])

def test_wrong_serial_stops_further_collection(tmp_path):
    client=Client([identity('000000000002')]);result=run(tmp_path,client)
    assert not result['complete'] and len(client.calls)==1
    assert result['records'][0]['status']=='conflicting'

def test_failed_endpoint_keeps_success_and_remaining_steps(tmp_path):
    client=Client([identity(),b'<response status="error"><msg>denied</msg></response>',
                   b'<response status="success"><result/></response>',b'<response status="success"><result/></response>'])
    result=run(tmp_path,client)
    assert not result['complete'] and len(result['records'])==4
    assert result['records'][1]['status']=='collection_failed'
    assert len(list(tmp_path.glob('*.native')))==3

def test_cancel_before_request_does_not_contact_device(tmp_path):
    client=Client([]);result=run(tmp_path,client,cancelled=lambda:True)
    assert result['cancelled'] and not client.calls


def test_retry_only_failed_steps_and_reproves_identity(tmp_path):
    ok=b'<response status="success"><result><config/></result></response>'
    initial=run(tmp_path,Client([identity(),b'<response status="error"/>',ok,ok]))
    retained={p.name:p.read_bytes() for p in tmp_path.iterdir()}
    retry=Client([identity(),ok])
    result=run(tmp_path,retry,retry_records=initial['records'])
    assert result['requested_steps']==['identity','local_configuration']
    assert result['complete'] and len(retry.calls)==2
    for name,raw in retained.items():assert (tmp_path/name).read_bytes()==raw
    initial['records'][0]['scope']['serial']='000000000002'
    rejected=Client([])
    with pytest.raises(ValueError,match='different device'):
        run(tmp_path,rejected,retry_records=initial['records'])
    assert not rejected.calls
