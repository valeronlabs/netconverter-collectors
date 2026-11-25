import pytest
from core.capture_evidence import receipt, store_receipt, validate_receipt, assess_attachment


def make(**kwargs):
    values = dict(vendor="synthetic",scope={"serial":"device-1","vsys":"vsys1"},
                  kind="usage",collector_version="test",payload=b"<usage/>",
                  observed_at="2026-01-01T00:00:00+00:00")
    values.update(kwargs)
    return receipt(**values)


def test_empty_capture_is_not_verified_absence():
    assert make(payload=b"")["status"] == "captured"
    with pytest.raises(ValueError): make(status="verified_absent")
    assert make(status="verified_absent",complete=True,absence_verified=True)["status"] == "verified_absent"


def test_scope_and_time_are_part_of_identity():
    original = make()
    assert original["id"] != make(scope={"serial":"device-2","vsys":"vsys1"})["id"]
    assert original["id"] != make(observed_at="2026-01-02T00:00:00Z")["id"]
    with pytest.raises(ValueError): make(observed_at="2026-01-01T00:00:00")


def test_retry_keeps_failure_and_success_receipts(tmp_path):
    failed = make(payload=None,status="collection_failed",failure_code="permission_denied")
    store_receipt(tmp_path,failed)
    successful=make();store_receipt(tmp_path,successful,b"<usage/>")
    assert len(list(tmp_path.glob('*.json'))) == 2
    with pytest.raises(ValueError):store_receipt(tmp_path,successful,b"different")


@pytest.mark.parametrize('field,value', [('id','0'*64), ('source_revision','invalid'),
    ('observed_at',None), ('complete','false'), ('sha256','0'*64), ('scope',{})])
def test_import_rejects_modified_receipt(field,value):
    record=make();record[field]=value
    with pytest.raises((ValueError, TypeError)):
        validate_receipt(record,b'<usage/>')


def test_scope_copy_and_corrupt_existing_payload(tmp_path):
    scope={'serial':'device-1','contexts':['vsys1']}
    record=make(scope=scope);scope['contexts'].append('vsys2')
    assert record['scope']['contexts']==['vsys1']
    store_receipt(tmp_path,record,b'<usage/>')
    (tmp_path/(record['id']+'.native')).write_bytes(b'changed')
    with pytest.raises(ValueError,match='Existing evidence'):
        store_receipt(tmp_path,record,b'<usage/>')


def test_attachment_only_resolves_matching_capture_not_translation():
    record=make(source_revision='a'*64)
    context=dict(vendor='synthetic',scope=record['scope'],source_revision='a'*64)
    assert assess_attachment(record,b'<usage/>',**context)['state']=='not_interpreted'
    result=assess_attachment(record,b'<usage/>',**context,native_identity_verified=True)
    assert result['resolves_missing_capture']
    assert not result['resolves_translation_limitations']
    context['source_revision']='b'*64
    assert assess_attachment(record,b'<usage/>',**context,native_identity_verified=True)['state']=='stale_or_incompatible'
    context['scope']={'serial':'different'}
    assert assess_attachment(record,b'<usage/>',**context,native_identity_verified=True)['state']=='conflicting'
