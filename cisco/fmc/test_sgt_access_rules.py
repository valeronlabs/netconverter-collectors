"""SGT flatten + harvest from Access Policy rules (TrustSec / ISE)."""

from __future__ import annotations

import unittest

import build_html
import fmc_collect_data as collector


class SgtAccessRulesTests(unittest.TestCase):
    def test_flatten_access_rule_keeps_source_and_dest_sgts(self) -> None:
        rule = {
            "name": "tim access",
            "id": "rule-1",
            "action": "ALLOW",
            "enabled": True,
            "metadata": {"section": "mandatory", "ruleIndex": 1},
            "sourceSecurityGroupTags": {
                "objects": [
                    {
                        "name": "SGT1",
                        "id": "sgt-1",
                        "type": "SecurityGroupTag",
                        "tag": 16,
                    }
                ]
            },
            "destinationSecurityGroupTags": {
                "objects": [
                    {"name": "Servers", "id": "sgt-2", "type": "SecurityGroupTag"}
                ]
            },
        }
        flat = collector.flatten_access_rule("AccessPolicy2", "pol-1", rule)
        self.assertEqual(flat["source_sgts"], "SGT1")
        self.assertEqual(flat["dest_sgts"], "Servers")

    def test_harvest_builds_catalog_and_references(self) -> None:
        pol_rules = {
            "accessrules": [
                {
                    "name": "tim access",
                    "id": "rule-1",
                    "sourceSecurityGroupTags": {
                        "objects": [
                            {
                                "name": "SGT1",
                                "id": "sgt-1",
                                "type": "SecurityGroupTag",
                            }
                        ]
                    },
                },
                {
                    "name": "no sgt",
                    "id": "rule-2",
                    "sourceNetworks": {"objects": [{"name": "any", "id": "n1"}]},
                },
            ]
        }
        catalog, refs = collector.harvest_sgts_from_access_rules(
            [("AccessPolicy2", "pol-1", pol_rules)]
        )
        self.assertEqual(len(catalog), 1)
        self.assertEqual(catalog[0]["name"], "SGT1")
        self.assertEqual(catalog[0]["id"], "sgt-1")
        self.assertTrue(catalog[0]["referenced_in_access_rules"])
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["direction"], "source")
        self.assertEqual(refs[0]["policy"], "AccessPolicy2")
        self.assertEqual(refs[0]["rule"], "tim access")

    def test_collector_and_html_versions_match(self) -> None:
        self.assertEqual(collector.__version__, build_html.__version__)


if __name__ == "__main__":
    unittest.main()
