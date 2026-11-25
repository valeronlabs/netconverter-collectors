import pytest
from defusedxml.common import DefusedXmlException
from palo.common.rule_usage_evidence import inspect_usage

RESPONSE = b'''<response status="success"><result><rule-hit-count><device-group>
<entry name="synthetic-group"><rule-base><entry name="security"><rules>
<entry name="same-name"><rule-state>Unused</rule-state><all-connected>yes</all-connected><rule-modification-timestamp>42</rule-modification-timestamp></entry>
<entry name="same-name"><rule-state>Partial</rule-state></entry>
</rules></entry></rule-base></entry></device-group></rule-hit-count></result></response>'''


def test_retained_states_do_not_become_numeric_counters_or_device_evidence():
    value = inspect_usage(RESPONSE)
    assert [r["state"] for r in value["records"]] == ["unused", "partial"]
    assert value["observation_time"] is None and value["serial"] is None
    assert value["rulebase_position"] is None
    assert not value["packet_counters"] and not value["cleanup_authorization"]
    assert len(value["records"]) == 2  # Repeated names retain distinct observations.


def test_empty_response_cannot_prove_absence():
    value = inspect_usage(b'<response status="success"><result><rule-hit-count/></result></response>')
    assert not value["complete_capture"] and value["records"] == []


def test_unrecognized_state_is_visible():
    value = inspect_usage(RESPONSE.replace(b"Unused", b"Unexpected"))
    assert value["records"][0]["state"] == "not_interpreted"


def test_failed_or_entity_response_refused():
    with pytest.raises(ValueError): inspect_usage(RESPONSE.replace(b"success", b"error"))
    with pytest.raises(DefusedXmlException): inspect_usage(b'<!DOCTYPE x [<!ENTITY e "x">]>' + RESPONSE)
