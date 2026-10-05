"""Unit tests for the Comment2Shell payload builders and helpers.

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import comment2shell as c2s


class HelperTests(unittest.TestCase):
    def test_rand_str_length_and_alphabet(self):
        value = c2s.rand_str()
        self.assertEqual(len(value), 8)
        self.assertTrue(all(c in "abcdefghijklmnopqrstuvwxyz0123456789" for c in value))
        self.assertEqual(len(c2s.rand_str(16)), 16)

    def test_normalize_url(self):
        self.assertEqual(c2s.normalize_url("example.com"), "https://example.com")
        self.assertEqual(c2s.normalize_url("http://example.com/"), "http://example.com")
        self.assertEqual(c2s.normalize_url("https://a.b/p/"), "https://a.b/p")

    def test_parse_version(self):
        self.assertEqual(c2s.parse_version("6.4.3"), (6, 4, 3))
        self.assertEqual(c2s.parse_version("WordPress 4.7"), (4, 7, 0))
        self.assertEqual(c2s.parse_version("5.0"), (5, 0, 0))
        self.assertIsNone(c2s.parse_version("no version here"))


class VulnerabilityRangeTests(unittest.TestCase):
    def test_branch_threshold(self):
        self.assertTrue(c2s.is_vulnerable((7, 1, 0)))
        self.assertFalse(c2s.is_vulnerable((7, 1, 1)))
        self.assertTrue(c2s.is_vulnerable((6, 4, 10)))
        self.assertFalse(c2s.is_vulnerable((6, 4, 11)))
        self.assertTrue(c2s.is_vulnerable((4, 7, 35)))
        self.assertFalse(c2s.is_vulnerable((4, 7, 36)))

    def test_unknown_branch_uses_range(self):
        self.assertFalse(c2s.is_vulnerable((4, 6, 0)))
        self.assertFalse(c2s.is_vulnerable((7, 2, 0)))

    def test_none(self):
        self.assertIsNone(c2s.is_vulnerable(None))


class DetectionPayloadTests(unittest.TestCase):
    def test_shape_without_callback(self):
        js = c2s.build_detection_js()
        self.assertTrue(js.startswith("(function(){"))
        self.assertTrue(js.endswith("})()"))
        self.assertIn("C2S_XSS_", js)

    def test_callback_is_used_and_escaped(self):
        js = c2s.build_detection_js('http://c/";x')
        self.assertIn("hit=", js)
        self.assertIn('\\"', js)


class RcePayloadTests(unittest.TestCase):
    def test_no_single_quotes(self):
        self.assertNotIn("'", c2s.build_rce_js())
        self.assertNotIn("'", c2s.build_rce_js(shell_path="abc123/abc123.php", marker="MZ"))

    def test_run_once_guard_and_encoder(self):
        js = c2s.build_rce_js()
        self.assertIn("window.c2s", js)
        self.assertIn("String.fromCharCode", js)
        self.assertIn("alert(", js)

    def test_shell_path_controls_plugin_dir(self):
        js = c2s.build_rce_js(shell_path="dirx/dirx.php")
        self.assertIn(c2s._js_string_from_chars("dirx"), js)


class StringEncoderTests(unittest.TestCase):
    def test_char_codes(self):
        self.assertEqual(c2s._js_string_from_chars("Az"), "String.fromCharCode(65,122)")


class XssCommentTests(unittest.TestCase):
    def test_builds_attribute_payload(self):
        out = c2s.build_xss_comment("a<b>c&d")
        self.assertIn('<blockquote cite="a', out)
        self.assertIn("onfocus=", out)
        self.assertIn("autofocus", out)
        self.assertIn("tabindex=0", out)
        self.assertIn("&lt;", out)
        self.assertIn("&gt;", out)
        self.assertIn("&amp;", out)

    def test_rejects_single_quotes(self):
        with self.assertRaises(ValueError):
            c2s.build_xss_comment("var x='y'")


if __name__ == "__main__":
    unittest.main()
