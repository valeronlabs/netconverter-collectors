"""Offline branded VPN map assets preserve the existing captured graph."""
from copy import deepcopy
import json
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import unittest
from unittest.mock import patch

from fortinet.fortimanager.build_html import build_vpn_graph, build_vpn_map


class Site:
    def page(self, path, title, body):
        self.path, self.title, self.body = path, title, body


class DiagramIconTests(unittest.TestCase):
    def snapshot(self):
        return {'devices':[{'name':'edge</script><script>bad()</script>','ip':'192.0.2.1'}],
            'vpn_phase1':[{'device':'edge</script><script>bad()</script>', 'name':'tunnel-A','remote_gw':'198.51.100.1','interface':'wan1'}],
            'vpn_phase2':[{'device':'edge</script><script>bad()</script>','phase1':'tunnel-A','src_subnet':'10.1.0.0/24','dst_subnet':'10.2.0.0/24'}]}

    def test_canonical_vectors_embedded_and_graph_unchanged(self):
        from core.diagram_shared import icon_svg
        snapshot=self.snapshot();original=deepcopy(snapshot)
        graph=build_vpn_graph(snapshot)
        site=Site();build_vpn_map(site,snapshot)
        encoded=re.search(r'var VPN_GRAPH = (.*?); var VPN_ICONS = (.*?);</script>',site.body)
        self.assertIsNotNone(encoded)
        self.assertEqual(json.loads(encoded[1]),graph)
        icons=json.loads(encoded[2])
        self.assertEqual(icons['device'],icon_svg('nc-firewall'))
        self.assertEqual(icons['peer'],icon_svg('nc-gateway'))
        self.assertEqual(icons['lnet'],icon_svg('nc-subnet'))
        self.assertIn('document.importNode(parsed,true)',site.body)
        self.assertIn('cloneNode(true)',site.body)
        self.assertNotIn('</script><script>bad()',site.body)
        self.assertNotIn('https://', ''.join(icons.values()))
        self.assertEqual(snapshot,original)

    def test_missing_assets_disclosed_without_losing_map(self):
        site=Site()
        with patch('core.diagram_shared.icon_svg', side_effect=KeyError('asset unavailable')):
            build_vpn_map(site,self.snapshot())
        self.assertIn('diagram assets unavailable',site.body)
        self.assertIn('VPN_GRAPH',site.body)
        self.assertIn('tunnel-A',site.body)


if __name__=='__main__':unittest.main()
