"""
Unit tests for SentinelFlow modules using mock fixtures.
"""

import unittest
from unittest.mock import MagicMock, patch

from src.analyzer import analyze_with_groq
from src.config import validate_config
from src.enrichment import enrich_with_virustotal
from src.notifier import send_to_discord
from src.sentinel_flow import process_alert


class TestSentinelFlow(unittest.TestCase):

    def test_config_validation(self):
        """Test configuration validator runs without error."""
        status = validate_config()
        self.assertIn("virustotal", status)
        self.assertIn("groq", status)
        self.assertIn("discord", status)

    @patch("requests.get")
    def test_enrichment_clean_domain(self, mock_get):
        """Test enrichment on clean domain returning 200."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 80,
                        "undetected": 10
                    }
                }
            }
        }
        mock_get.return_value = mock_response

        res = enrich_with_virustotal("example.com", api_key="dummy_key")
        self.assertTrue(res["vt_available"])
        self.assertEqual(res["reputation"], "CLEAN")
        self.assertEqual(res["malicious"], 0)

    @patch("requests.get")
    def test_enrichment_malicious_domain(self, mock_get):
        """Test enrichment on malicious domain."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 14,
                        "suspicious": 3,
                        "harmless": 2,
                        "undetected": 0
                    }
                }
            }
        }
        mock_get.return_value = mock_response

        res = enrich_with_virustotal("malware-traffic.org", api_key="dummy_key")
        self.assertTrue(res["vt_available"])
        self.assertEqual(res["reputation"], "SUSPICIOUS")
        self.assertEqual(res["malicious"], 14)

    def test_analyzer_heuristic_fallback(self):
        """Test fallback heuristic when Groq key is absent."""
        vt_data_clean = {"vt_available": True, "malicious": 0, "suspicious": 0}
        res_clean = analyze_with_groq({"alertId": "1"}, vt_data_clean, api_key="")
        self.assertEqual(res_clean["severity"], "Low")

        vt_data_malicious = {"vt_available": True, "malicious": 7, "suspicious": 0}
        res_mal = analyze_with_groq({"alertId": "2"}, vt_data_malicious, api_key="")
        self.assertEqual(res_mal["severity"], "Critical")

    @patch("requests.post")
    def test_discord_notifier_success(self, mock_post):
        """Test Discord webhook payload delivery."""
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_post.return_value = mock_response

        alert = {"alertId": "TEST-1", "dstDomain": "example.com"}
        vt = {"vt_available": True, "malicious": 0, "suspicious": 0, "reputation": "CLEAN"}
        ai = {"severity": "Low", "reason": "Known benign site"}

        success = send_to_discord(alert, vt, ai, webhook_url="https://discord.com/api/webhooks/test/test")
        self.assertTrue(success)


if __name__ == "__main__":
    unittest.main()
