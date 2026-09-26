import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('render', ROOT/'web/pilot-reports/render.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class Reports(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT/'docs/pilot-reports.json').read_text())

    def test_snapshot(self):
        page = r.render(self.data)
        for phrase in ['Ace', 'Mako', 'Not yet pilot enrolled', 'Historical results, not live authorization.', 'Not established', 'Evidence basis / limits']:
            self.assertIn(phrase, page)
        self.assertNotIn('<script', page)
        self.assertNotIn('<form', page)

    def test_extra_private_fields_rejected(self):
        self.data['devices'][0]['serial'] = 'private'
        with self.assertRaises(ValueError): r.render(self.data)

    def test_unknown_result_rejected(self):
        self.data['devices'][0]['tests'][0]['status'] = 'qualified'
        with self.assertRaises(ValueError): r.render(self.data)

    def test_duplicate_slug_rejected(self):
        self.data['devices'].append(copy.deepcopy(self.data['devices'][0]))
        with self.assertRaises(ValueError): r.render(self.data)

    def test_newer_device_rejected(self):
        self.data['devices'][0]['as_of'] = '9999-12-31'
        with self.assertRaises(ValueError): r.render(self.data)

    def test_text_escaped(self):
        self.data['devices'][0]['summary'] = '<script>alert("x")</script>'
        self.data['devices'][0]['name'] = '"><img src=x>'
        page = r.render(self.data)
        self.assertNotIn('<script>', page)
        self.assertNotIn('<img', page)
        self.assertIn('&lt;script&gt;', page)

    def test_navigation_and_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); home=p/'index.html'
            home.write_text((ROOT/'internal/provisioning/stationui/web/index.html').read_text())
            with patch('sys.argv', ['render', str(ROOT/'docs/pilot-reports.json'), str(p/'pilot'), str(home)]): r.main()
            self.assertEqual(json.loads((p/'pilot/reports.json').read_text()), self.data)
            self.assertIn('href="./pilot/index.html"', home.read_text())
            self.assertIn('href="../index.html"', (p/'pilot/index.html').read_text())
            self.assertIn('href="./reports.json"', (p/'pilot/index.html').read_text())

class PublishedReports(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('KAIBA_STATION_PAGES'), 'requires built Pages bundle')
    def test_packaged_site_has_only_expected_homepage_change(self):
        pages = Path(os.environ['KAIBA_STATION_PAGES'])
        original = (ROOT/'internal/provisioning/stationui/web/index.html').read_text()
        published = (pages/'index.html').read_text()
        navigation = '    <nav aria-label="Project reports"><a href="./pilot/index.html">Pilot enrollment reports</a></nav>\n\n'
        self.assertEqual(published.count(navigation), 1)
        self.assertEqual(published.replace(navigation, '', 1), original)
        data = json.loads((ROOT/'docs/pilot-reports.json').read_text())
        self.assertEqual(json.loads((pages/'pilot/reports.json').read_text()), data)
        self.assertEqual((pages/'pilot/index.html').read_text(), r.render(data))
        self.assertEqual((pages/'pilot/styles.css').read_bytes(), (ROOT/'web/pilot-reports/styles.css').read_bytes())


if __name__ == '__main__':
    unittest.main()
