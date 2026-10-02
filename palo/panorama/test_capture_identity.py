from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.capture_identity import native_identity


def test_identity_is_exact_and_does_not_authenticate_other_response_kinds():
    raw=b'<response status="success"><result><system><serial>000000000001</serial></system></result></response>'
    assert native_identity('identity',raw,'000000000001')=='matching'
    assert native_identity('identity',raw,'000000000002')=='conflicting'
    assert native_identity('routing',raw,'000000000001')=='unverified'


def test_manager_assignment_and_unidentified_config_are_not_device_identity():
    assert native_identity('local_configuration',b'<config><devices><entry name="localhost.localdomain"/></devices></config>','000000000001')=='unverified'
    assert native_identity('local_configuration',b'<config serial="000000000001"><mgt-config><devices/></mgt-config></config>','000000000001')=='unverified'
    assert native_identity('local_configuration',b'<config serial="000000000001"/>','000000000001')=='matching'


def test_unsafe_or_failed_response_is_not_identity_evidence():
    for raw in [b'<!DOCTYPE x [<!ENTITY a "000000000001">]><response/>',b'<response status="error"/>',b'invalid']:
        assert native_identity('identity',raw,'000000000001')=='unverified'
