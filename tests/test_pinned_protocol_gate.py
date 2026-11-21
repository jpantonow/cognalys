import unittest


import _paths  # noqa: E402,F401  (project import paths)

from cognalys.llm.contract_gates import pinned_negotiated_protocol  # noqa: E402

PATH = "app/src/main/java/org/app/HttpClients.kt"


def _edit(before, after, path=PATH):
    return {"source_file_path": path, "edit_kind": "method",
            "original_code": before, "corrected_code": after}


class PinnedProtocolTests(unittest.TestCase):
    """Session's patch turned getInstance("SSL") into getInstance("TLSv1.2")."""

    def test_pinning_a_negotiated_selector_is_refused(self):
        issues = pinned_negotiated_protocol({}, [_edit(
            'val ctx = SSLContext.getInstance("SSL")', 'val ctx = SSLContext.getInstance("TLSv1.2")')])
        self.assertEqual(issues[0]["code"], "PINNED_NEGOTIATED_PROTOCOL")
        self.assertIn('"TLS"', issues[0]["details"][0])

    def test_negotiating_replacements_and_old_pins_pass(self):
        self.assertEqual(pinned_negotiated_protocol({}, [_edit(
            'SSLContext.getInstance("SSL")', 'SSLContext.getInstance("TLS")')]), [])
        self.assertEqual(pinned_negotiated_protocol({}, [_edit(
            'SSLContext.getInstance("TLSv1")', 'SSLContext.getInstance("TLSv1.2")')]), [])
        self.assertEqual(pinned_negotiated_protocol({}, [_edit(
            'SSLContext.getInstance("SSL")', 'SSLContext.getInstance("TLSv1.2")',
            path="app/src/test/java/org/app/HttpClientsTest.kt")]), [])


class ProtocolListTests(unittest.TestCase):
    """fread's patch rewrote protocols = arrayOf("SSLv3") as arrayOf("TLSv1.2")."""

    def test_only_dropping_tls13_is_refused(self):
        refused = pinned_negotiated_protocol({}, [_edit(
            'p.protocols = arrayOf("TLSv1.2", "TLSv1.3")', 'p.protocols = arrayOf("TLSv1.2")')])
        self.assertEqual(refused[0]["code"], "PINNED_NEGOTIATED_PROTOCOL")
        # An improvement that is not ideal passes: SSLv3 out, TLSv1.2 in; TLS 1.1 out.
        self.assertEqual(pinned_negotiated_protocol({}, [_edit(
            'sslContext.defaultSSLParameters.protocols = arrayOf("SSLv3")',
            'sslContext.defaultSSLParameters.protocols = arrayOf("TLSv1.2")')]), [])
        self.assertEqual(pinned_negotiated_protocol({}, [_edit(
            'socket.setEnabledProtocols(new String[]{"TLSv1.1", "TLSv1.2"})',
            'socket.setEnabledProtocols(new String[]{"TLSv1.2"})')]), [])
        self.assertEqual(pinned_negotiated_protocol({}, [_edit(
            'socket.setEnabledProtocols(new String[]{"TLSv1.1", "TLSv1.2"})',
            'socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"})')]), [])
        self.assertEqual(pinned_negotiated_protocol({}, [_edit(
            'p.protocols = arrayOf("TLSv1.2")', 'p.protocols = arrayOf("TLSv1.2")')]), [])


class RetryTargetTests(unittest.TestCase):
    def test_a_refused_behaviour_regenerates_its_planned_tests(self):
        from cognalys.llm.semantic_validation import semantic_validation_retry_targets
        paths = [PATH, "app/src/test/java/org/app/HttpClientsTest.kt"]
        errors = [{"code": "PINNED_NEGOTIATED_PROTOCOL", "path": PATH}]
        self.assertEqual(semantic_validation_retry_targets(errors, paths), set(paths))


if __name__ == "__main__":
    unittest.main()
