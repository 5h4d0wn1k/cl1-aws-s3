import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import s3_scanner as mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO, "fixtures", "s3-buckets.json")


class TestS3Parsers(unittest.TestCase):

    def test_parse_list_objects(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Contents><Key>data/x.csv</Key><Size>123</Size>
    <LastModified>2026-01-01T00:00:00Z</LastModified>
    <StorageClass>STANDARD</StorageClass></Contents>
</ListBucketResult>"""
        objs = mod.S3Scanner._parse_list_objects(xml)
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]["key"], "data/x.csv")
        self.assertEqual(objs[0]["size"], 123)

    def test_parse_acl_public_grant(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>exampleownerid</ID></Owner>
  <AccessControlList>
    <Grant>
      <Grantee xsi:type="Group" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
      </Grantee>
      <Permission>READ</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>"""
        acl = mod.S3Scanner._parse_acl(xml)
        self.assertEqual(acl["grants"][0]["permission"], "READ")
        self.assertIn("AllUsers", acl["grants"][0]["uri"])

    def test_permission_severity_map(self):
        self.assertEqual(mod.PERMISSION_SEVERITY["WRITE"], "CRITICAL")
        self.assertEqual(mod.PERMISSION_SEVERITY["READ"], "MEDIUM")
        self.assertEqual(mod.PERMISSION_SEVERITY["FULL_CONTROL"], "CRITICAL")

    def test_normalise_acl_grants_aliases_public_uris(self):
        grants = mod._normalise_acl_grants(
            [{"grantee": "AllUsers", "permission": "READ"},
             {"grantee": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
              "permission": "WRITE"}])
        self.assertEqual(grants[0]["uri"],
                         "http://acs.amazonaws.com/groups/global/AllUsers")
        self.assertEqual(grants[1]["permission"], "WRITE")


class TestS3OfflineAuditor(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(FIXTURE, encoding="utf-8") as fh:
            cls.fixture = json.load(fh)

    def setUp(self):
        self.auditor = mod.S3OfflineAuditor()

    def test_audits_fixture_with_findings(self):
        findings = self.auditor.audit(self.fixture["buckets"])
        self.assertGreater(len(findings), 0)
        for f in findings:
            self.assertIn("severity", f)
            self.assertIn("remediation", f)
            self.assertIn("category", f)
            self.assertIn("rule_id", f)

    def test_public_acl_grant_detected(self):
        bucket = {
            "name": "public",
            "acl_grants": [
                {"grantee": "http://acs.amazonaws.com/groups/global/AllUsers",
                 "permission": "WRITE"}
            ],
        }
        findings = self.auditor.audit([bucket])
        acl = [f for f in findings if f["category"] == "bucket_acl"]
        self.assertEqual(len(acl), 1)
        self.assertEqual(acl[0]["severity"], "CRITICAL")

    def test_public_policy_detected(self):
        bucket = {
            "name": "policy",
            "policy_statements": [{"effect": "Allow", "principal": "*",
                                   "action": "s3:GetObject"}],
        }
        findings = self.auditor.audit([bucket])
        self.assertTrue(any(f["category"] == "bucket_policy" for f in findings))

    def test_private_bucket_no_public_findings(self):
        bucket = {
            "name": "private",
            "acl_grants": [],
            "policy_statements": [
                {"effect": "Allow",
                 "principal": {"AWS": ["arn:aws:iam::192000000002:root"]},
                 "action": "s3:GetObject"}
            ],
            "versioning": "Enabled",
            "logging": {"enabled": True},
            "encryption": {"rule": {"sse_algorithm": "AES256"}},
            "public_access_block": {
                "block_public_acls": True, "ignore_public_acls": True,
                "block_public_policy": True, "restrict_public_buckets": True},
        }
        findings = self.auditor.audit([bucket])
        self.assertEqual([f for f in findings if f["severity"] in ("CRITICAL", "HIGH")], [])

    def test_missing_config_flags(self):
        bucket = {"name": "bare", "acl_grants": []}
        findings = self.auditor.audit([bucket])
        cats = {f["category"] for f in findings}
        self.assertTrue({"versioning", "logging", "encryption", "public_access_block"} <= cats)

    def test_load_fixture(self):
        buckets = mod.load_bucket_fixtures(FIXTURE)
        self.assertEqual(len(buckets), 3)


class TestSignatureHelpers(unittest.TestCase):

    def test_hmac_and_signature_key_path(self):
        scanner = mod.S3Scanner("AKIAEXAMPLE", "verysecret", "us-east-1")
        key = scanner._get_signing_key("20260101")
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)

    def test_sha256(self):
        self.assertEqual(
            mod.S3Scanner._sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )


if __name__ == "__main__":
    unittest.main()