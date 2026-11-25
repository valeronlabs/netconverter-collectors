from io import BytesIO
import json
import zipfile
import pytest

from core.capture_bundle import build_bundle, read_bundle
from core.capture_evidence import receipt


def test_builder_refuses_oversized_response_before_zip_allocation(monkeypatch):
    import core.capture_bundle as module
    raw=b'xxxxxxxx'
    record=receipt(vendor='cisco_asa',scope={'device':'one'},kind='configuration',
        collector_version='test',payload=raw)
    monkeypatch.setattr(module,'MAX_RESPONSE',4)
    monkeypatch.setattr(module,'BytesIO',lambda:pytest.fail('must reject before ZIP allocation'))
    with pytest.raises(ValueError,match='Response size limit'):
        build_bundle([(record,raw)])


def test_builder_bounds_generator_before_consuming_all_rows(monkeypatch):
    import core.capture_bundle as module
    record=receipt(vendor='cisco_asa',scope={'device':'one'},kind='configuration',
        collector_version='test',status='missing')
    monkeypatch.setattr(module,'MAX_RECORDS',1)
    def rows():
        yield record,None
        yield record,None
        pytest.fail('must not consume beyond record limit')
    with pytest.raises(ValueError,match='record limit'):
        build_bundle(rows())


@pytest.mark.parametrize('vendor', ['palo_alto','checkpoint','cisco_fmc','fortinet','cisco_asa'])
def test_exact_roundtrip_and_failed_steps(vendor):
    raw = b'synthetic native bytes\r\n'
    success = receipt(vendor=vendor,scope={'device':'one'},kind='configuration',
        collector_version='test',payload=raw,source_revision='a'*64)
    failed = receipt(vendor=vendor,scope={'device':'one'},kind='routing',
        collector_version='test',status='collection_failed',failure_code='permission_denied',source_revision='a'*64)
    result = read_bundle(build_bundle([(success,raw),(failed,None)]))
    assert result['records']==[(success,raw),(failed,None)]
    assert not success['complete']


def mutated(extra_name=None, corrupt=False):
    raw=b'native'
    record=receipt(vendor='palo_alto',scope={'serial':'000000000001'},kind='identity',collector_version='test',payload=raw)
    valid=build_bundle([(record,raw)])
    output=BytesIO()
    with zipfile.ZipFile(BytesIO(valid)) as source, zipfile.ZipFile(output,'w') as target:
        for member in source.infolist():
            payload=source.read(member.filename)
            if corrupt and member.filename.endswith('.native'):payload=b'changed'
            target.writestr(member.filename,payload)
        if extra_name:target.writestr(extra_name,b'unaccounted')
    return output.getvalue()


@pytest.mark.parametrize('name',['../escape','/absolute','evidence\\escape','unexpected.txt','evidence/'+('b'*64)+'.native'])
def test_rejects_unaccounted_and_unsafe_members(name):
    with pytest.raises(ValueError):read_bundle(mutated(name))


def test_rejects_changed_native_bytes():
    with pytest.raises(ValueError):read_bundle(mutated(corrupt=True))


def test_manifest_duplicate_json_fields_rejected():
    output=BytesIO()
    with zipfile.ZipFile(output,'w') as archive:
        archive.writestr('manifest.json','{"schema":"nc.capture-bundle.v1","receipts":[],"receipts":[]}')
    with pytest.raises(ValueError):read_bundle(output.getvalue())


def test_expanded_limit(monkeypatch):
    import core.capture_bundle as module
    raw=mutated()
    monkeypatch.setattr(module,'MAX_RESPONSE',1)
    with pytest.raises(ValueError,match='size limit'):read_bundle(raw)


def test_package_directory_preserves_exact_receipts(tmp_path):
    from core.capture_bundle import bundle_directory
    from core.capture_evidence import store_receipt
    raw=b'synthetic\r\n'
    record=receipt(vendor='checkpoint',scope={'gateway_uid':'one'},kind='identity',collector_version='test',payload=raw)
    store_receipt(tmp_path,record,raw)
    (tmp_path/'job.json').write_text('{"status":"complete"}')
    assert read_bundle(bundle_directory(tmp_path))['records']==[(record,raw)]
