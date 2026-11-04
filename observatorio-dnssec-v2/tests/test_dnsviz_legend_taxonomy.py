import json
import unittest
from pathlib import Path


TAXONOMY_PATH = Path("backend/data/dnsviz/dnsviz-legend-taxonomy.json")


class DNSVizLegendTaxonomyTests(unittest.TestCase):
    def setUp(self):
        self.taxonomy = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))

    def test_source_is_official_dnsviz_documentation(self):
        self.assertEqual(
            self.taxonomy["source"]["url"],
            "https://dnsviz.net/doc/dnssec/",
        )
        self.assertTrue(
            self.taxonomy["principles"]["separate_visual_legend_from_operational_interpretation"]
        )
        self.assertTrue(self.taxonomy["principles"]["canonical_legend_is_not_a_validator"])

    def test_entries_have_three_separate_layers(self):
        entries = self.taxonomy["entries"]
        self.assertEqual(len(entries), 42)
        self.assertEqual(len({entry["id"] for entry in entries}), 42)

        for entry in entries:
            with self.subTest(entry=entry["id"]):
                self.assertIn("canonical_dnsviz_legend", entry)
                self.assertIn("localization", entry)
                self.assertIn("operational_interpretation", entry)
                self.assertEqual(
                    entry["canonical_dnsviz_legend"]["source_url"],
                    "https://dnsviz.net/doc/dnssec/",
                )
                self.assertIn("en", entry["localization"])
                self.assertIn("es", entry["localization"])

    def test_canonical_examples_match_dnsviz_legend_terms(self):
        by_id = {entry["id"]: entry for entry in self.taxonomy["entries"]}

        self.assertEqual(
            by_id["delegation_secure"]["canonical_dnsviz_legend"]["visual"]["edge"],
            "solid blue line",
        )
        self.assertEqual(
            by_id["delegation_bogus"]["canonical_dnsviz_legend"]["visual"]["edge"],
            "dashed red line",
        )
        self.assertEqual(
            by_id["node_secure"]["canonical_dnsviz_legend"]["visual"]["node_outline"],
            "blue",
        )
        self.assertEqual(
            by_id["response_error"]["canonical_dnsviz_legend"]["visual"]["icon"],
            "error icon with italic label",
        )

    def test_taxonomy_has_no_mojibake_markers(self):
        text = TAXONOMY_PATH.read_text(encoding="utf-8")
        self.assertNotRegex(text, "[ÃƒÃ‚Ã¢]")


if __name__ == "__main__":
    unittest.main()
