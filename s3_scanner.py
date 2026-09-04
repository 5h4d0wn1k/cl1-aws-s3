#!/usr/bin/env python3
"""CL1 — AWS S3 Bucket Scanner.

Enumerates S3 buckets, checks permissions, detects public access,
and lists bucket contents. Uses only standard library for AWS API signing.
"""

import argparse
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


class S3Scanner:
    """AWS S3 bucket scanner using standard library."""

    AWS4 = "AWS4-HMAC-SHA256"
    SERVICE = "s3"

    def __init__(self, aws_access_key: str, aws_secret_key: str, region: str = "us-east-1"):
        self.access_key = aws_access_key
        self.secret_key = aws_secret_key
        self.region = region
        self.session_token = None

    # ── AWS Signature V4 helpers ─────────────────────────────────────

    @staticmethod
    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _hmac_sha256(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def _get_signing_key(self, date_stamp: str) -> bytes:
        k_date = self._hmac_sha256(("AWS4" + self.secret_key).encode(), date_stamp)
        k_region = self._hmac_sha256(k_date, self.region)
        k_service = self._hmac_sha256(k_region, self.SERVICE)
        return self._hmac_sha256(k_service, "aws4_request")

    def _sign(self, method: str, url: str, headers: dict, payload: bytes = b"") -> dict:
        parsed = urllib.parse.urlparse(url)
        canonical_query = parsed.query or ""
        payload_hash = self._sha256(payload)
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        signed_header_list = sorted(
            h.lower() for h in {**headers, "host": parsed.hostname, "x-amz-date": amz_date}
        )
        canonical_headers = ""
        for h in signed_header_list:
            if h == "host":
                canonical_headers += f"host:{parsed.hostname}\n"
            elif h == "x-amz-date":
                canonical_headers += f"x-amz-date:{amz_date}\n"
            elif h in headers:
                canonical_headers += f"{h.lower()}:{headers[h]}\n"
        signed_headers = ";".join(signed_header_list)
        canonical_request = "\n".join([
            method, parsed.path or "/", canonical_query,
            canonical_headers, signed_headers, payload_hash,
        ])
        credential_scope = f"{date_stamp}/{self.region}/{self.SERVICE}/aws4_request"
        string_to_sign = "\n".join([
            self.AWS4, amz_date, credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ])
        signing_key = self._get_signing_key(date_stamp)
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        auth_header = (
            f"{self.AWS4} Credential={self.access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        final_headers = dict(headers)
        final_headers["x-amz-date"] = amz_date
        final_headers["Authorization"] = auth_header
        return final_headers

    # ── HTTP helpers ─────────────────────────────────────────────────

    def _request(self, method: str, url: str, body: bytes = b"") -> tuple[int, str]:
        headers = {"Host": urllib.parse.urlparse(url).hostname}
        headers = self._sign(method, url, headers, body)
        req = urllib.request.Request(url, data=body or None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(errors="replace")
        except Exception as exc:
            return 0, str(exc)

    def _request_unsigned(self, url: str) -> tuple[int, str]:
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(errors="replace")
        except Exception as exc:
            return 0, str(exc)

    # ── Bucket enumeration ───────────────────────────────────────────

    def list_buckets(self) -> list[str]:
        """List all S3 buckets owned by the caller."""
        status, body = self._request("GET", "https://s3.amazonaws.com/")
        if status != 200:
            print(f"[!] Failed to list buckets (HTTP {status})")
            return []
        root = ET.fromstring(body)
        ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
        return [b.find("s3:Name", ns).text for b in root.findall(".//s3:Bucket", ns) if b.find("s3:Name", ns) is not None]

    def enum_from_wordlist(self, base_url: str, wordlist: list[str]) -> list[str]:
        """Check which bucket names from a wordlist exist."""
        found = []
        for name in wordlist:
            url = f"https://{name}.s3.{self.region}.amazonaws.com/"
            status, _ = self._request_unsigned(url)
            if status == 200:
                print(f"  [+] EXISTS (public): {name}")
                found.append(name)
            elif status == 403:
                print(f"  [=] EXISTS (private): {name}")
                found.append(name)
        return found

    # ── Permission checks ────────────────────────────────────────────

    def check_anonymous_list(self, bucket: str) -> dict:
        """Check if bucket allows anonymous ListBucket."""
        url = f"https://{bucket}.s3.{self.region}.amazonaws.com/"
        status, body = self._request_unsigned(url)
        result = {"bucket": bucket, "anonymous_list": False, "status": status}
        if status == 200:
            result["anonymous_list"] = True
            result["objects"] = self._parse_list_objects(body)
        elif status == 403:
            result["message"] = "Access Denied — bucket exists, listing forbidden"
        return result

    def check_anonymous_read_object(self, bucket: str, key: str) -> dict:
        """Check if a specific object is anonymously readable."""
        url = f"https://{bucket}.s3.{self.region}.amazonaws.com/{urllib.parse.quote(key)}"
        status, body = self._request_unsigned(url)
        return {
            "bucket": bucket, "key": key,
            "anonymous_read": status == 200,
            "status": status,
            "size": len(body) if status == 200 else None,
        }

    def check_write_policy(self, bucket: str) -> dict:
        """Check if anonymous PUT is allowed."""
        url = f"https://{bucket}.s3.{self.region}.amazonaws.com/probe-write-test"
        data = b"permission-probe"
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "text/plain"}, method="PUT",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status_code = resp.status
        except urllib.error.HTTPError as exc:
            status_code = exc.code
        except Exception:
            status_code = 0
        writable = status_code == 200
        if writable:
            self._request("DELETE", f"https://{bucket}.s3.{self.region}.amazonaws.com/probe-write-test")
        return {"bucket": bucket, "anonymous_write": writable, "status": status_code}

    def check_acl(self, bucket: str) -> dict:
        """Retrieve bucket ACL."""
        url = f"https://{bucket}.s3.{self.region}.amazonaws.com/?acl"
        status, body = self._request("GET", url)
        result = {"bucket": bucket, "status": status}
        if status == 200:
            result["acl"] = self._parse_acl(body)
        return result

    def check_versioning(self, bucket: str) -> dict:
        """Check bucket versioning status."""
        url = f"https://{bucket}.s3.{self.region}.amazonaws.com/?versioning"
        status, body = self._request("GET", url)
        result = {"bucket": bucket, "status": status}
        if status == 200:
            root = ET.fromstring(body)
            ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
            state_el = root.find(".//s3:Status", ns)
            result["versioning"] = state_el.text if state_el is not None else "Suspended"
        return result

    def check_logging(self, bucket: str) -> dict:
        """Check bucket logging configuration."""
        url = f"https://{bucket}.s3.{self.region}.amazonaws.com/?logging"
        status, body = self._request("GET", url)
        result = {"bucket": bucket, "status": status}
        if status == 200:
            root = ET.fromstring(body)
            ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
            enabled = root.find(".//s3:Enabled", ns)
            result["logging_enabled"] = enabled is not None and enabled.text == "true"
        return result

    def check_encryption(self, bucket: str) -> dict:
        """Check default encryption."""
        url = f"https://{bucket}.s3.{self.region}.amazonaws.com/?encryption"
        status, body = self._request("GET", url)
        result = {"bucket": bucket, "status": status, "encrypted": status == 200}
        if status == 200:
            root = ET.fromstring(body)
            ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
            algo = root.find(".//s3:Rule//s3:SSEAlgorithm", ns)
            result["algorithm"] = algo.text if algo is not None else None
        return result

    # ── Content listing ──────────────────────────────────────────────

    def list_contents(self, bucket: str, prefix: str = "", max_keys: int = 1000) -> list[dict]:
        """List objects in a bucket."""
        params = f"max-keys={max_keys}"
        if prefix:
            params += f"&prefix={urllib.parse.quote(prefix)}"
        url = f"https://{bucket}.s3.{self.region}.amazonaws.com/?{params}"
        status, body = self._request_unsigned(url) if False else self._request("GET", url)
        if status != 200:
            url = f"https://{bucket}.s3.{self.region}.amazonaws.com/?{params}"
            status, body = self._request_unsigned(url)
        if status == 200:
            return self._parse_list_objects(body)
        print(f"[!] Cannot list {bucket} (HTTP {status})")
        return []

    # ── Full scan ────────────────────────────────────────────────────

    def scan_bucket(self, bucket: str) -> dict:
        """Perform full permission scan on a bucket."""
        print(f"\n{'='*60}")
        print(f"  Scanning: {bucket}")
        print(f"{'='*60}")

        results = {"bucket": bucket}

        anon = self.check_anonymous_list(bucket)
        results["anonymous_list"] = anon["anonymous_list"]
        print(f"  Anonymous List:  {'YES — PUBLIC' if anon['anonymous_list'] else 'No'}")

        if anon["anonymous_list"] and anon.get("objects"):
            print(f"  Objects found:   {len(anon['objects'])}")

        write = self.check_write_policy(bucket)
        results["anonymous_write"] = write["anonymous_write"]
        print(f"  Anonymous Write: {'YES — CRITICAL' if write['anonymous_write'] else 'No'}")

        acl = self.check_acl(bucket)
        results["acl"] = acl.get("acl", {})
        if acl.get("acl"):
            for grant in acl["acl"].get("grants", []):
                if "AllUsers" in grant.get("uri", "") or "AuthenticatedUsers" in grant.get("uri", ""):
                    print(f"  ACL Warning:     {grant['permission']} for {grant['grantee']}")

        ver = self.check_versioning(bucket)
        results["versioning"] = ver.get("versioning", "Unknown")
        print(f"  Versioning:      {ver.get('versioning', 'Unknown')}")

        log = self.check_logging(bucket)
        results["logging"] = log.get("logging_enabled", False)
        print(f"  Logging:         {'Enabled' if log.get('logging_enabled') else 'Disabled'}")

        enc = self.check_encryption(bucket)
        results["encryption"] = enc.get("encrypted", False)
        print(f"  Encryption:      {'Enabled' if enc.get('encrypted') else 'Disabled'}")

        public_score = sum([
            40 if anon["anonymous_list"] else 0,
            50 if write["anonymous_write"] else 0,
            5 if not log.get("logging_enabled") else 0,
            5 if not enc.get("encrypted") else 0,
        ])
        results["risk_score"] = min(public_score, 100)
        risk_label = "CRITICAL" if public_score >= 80 else "HIGH" if public_score >= 50 else "MEDIUM" if public_score >= 20 else "LOW"
        print(f"  Risk Score:      {public_score}/100 ({risk_label})")

        return results

    # ── Parsers ──────────────────────────────────────────────────────

    @staticmethod
    def _parse_list_objects(xml_body: str) -> list[dict]:
        root = ET.fromstring(xml_body)
        ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
        objects = []
        for obj in root.findall(".//s3:Contents", ns):
            key = obj.find("s3:Key", ns)
            size = obj.find("s3:Size", ns)
            modified = obj.find("s3:LastModified", ns)
            storage = obj.find("s3:StorageClass", ns)
            objects.append({
                "key": key.text if key is not None else "",
                "size": int(size.text) if size is not None else 0,
                "last_modified": modified.text if modified is not None else "",
                "storage_class": storage.text if storage is not None else "STANDARD",
            })
        return objects

    @staticmethod
    def _parse_acl(xml_body: str) -> dict:
        root = ET.fromstring(xml_body)
        ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
        grants = []
        for grant in root.findall(".//s3:Grant", ns):
            grantee_el = grant.find("s3:Grantee", ns)
            perm_el = grant.find("s3:Permission", ns)
            uri_el = grantee_el.find("s3:URI", ns) if grantee_el is not None else None
            id_el = grantee_el.find("s3:ID", ns) if grantee_el is not None else None
            grants.append({
                "grantee": uri_el.text if uri_el is not None else (id_el.text if id_el is not None else "unknown"),
                "permission": perm_el.text if perm_el is not None else "unknown",
                "uri": uri_el.text if uri_el is not None else "",
            })
        owner_el = root.find(".//s3:Owner", ns)
        owner_id = ""
        if owner_el is not None:
            id_el = owner_el.find("s3:ID", ns)
            owner_id = id_el.text if id_el is not None else ""
        return {"owner": owner_id, "grants": grants}


class BucketWordlist:
    """Common bucket name wordlist for enumeration."""

    COMMON_NAMES = [
        "backup", "backups", "config", "configs", "data", "database", "db",
        "dev", "development", "prod", "production", "staging", "stage",
        "logs", "log", "archive", "archives", "temp", "tmp", "test", "tests",
        "assets", "static", "media", "images", "img", "uploads", "files",
        "documents", "docs", "reports", "exports", "downloads",
        "secrets", "credentials", "keys", "tokens", "env", "environment",
        "deploy", "deployment", "ci", "cd", "pipeline", "build",
        "monitoring", "metrics", "analytics", "dashboard",
        "public", "private", "shared", "common", "internal",
        "users", "accounts", "sessions", "auth", "s3", "s3logs",
        "access-logs", "audit", "compliance", "security",
        "www", "web", "website", "cdn", "cache",
        "lambda", "serverless", "functions", "api",
    ]

    @classmethod
    def get_default(cls) -> list[str]:
        return list(cls.COMMON_NAMES)


def print_banner():
    banner = r"""
    ╔═══════════════════════════════════════════╗
    ║     CL1 — AWS S3 Bucket Scanner           ║
    ║     Standard Library · No Dependencies     ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="AWS S3 Bucket Scanner")
    parser.add_argument("--access-key", default="", help="AWS Access Key ID")
    parser.add_argument("--secret-key", default="", help="AWS Secret Access Key")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--bucket", default="", help="Specific bucket to scan")
    parser.add_argument("--enum", action="store_true", help="Enumerate buckets from wordlist")
    parser.add_argument("--list-objects", action="store_true", help="List bucket contents")
    parser.add_argument("--prefix", default="", help="Prefix filter for listing")
    parser.add_argument("--wordlist", nargs="*", help="Extra bucket names to check")
    parser.add_argument("--output", default="", help="JSON output file")
    args = parser.parse_args()

    scanner = S3Scanner(args.access_key, args.secret_key, args.region)
    all_results = []

    if args.bucket:
        result = scanner.scan_bucket(args.bucket)
        all_results.append(result)

        if args.list_objects:
            objects = scanner.list_contents(args.bucket, args.prefix)
            print(f"\n  Objects in {args.bucket}:")
            for obj in objects[:50]:
                print(f"    {obj['key']}  ({obj['size']} bytes)")
            if len(objects) > 50:
                print(f"    ... and {len(objects) - 50} more")

    if args.enum:
        print("\n[*] Enumerating buckets...")
        names = args.wordlist or BucketWordlist.get_default()
        found = scanner.enum_from_wordlist(
            f"https://s3.{args.region}.amazonaws.com", names,
        )
        print(f"\n[*] Found {len(found)} buckets")
        for name in found:
            result = scanner.scan_bucket(name)
            all_results.append(result)

    if args.access_key:
        print("\n[*] Listing owned buckets...")
        owned = scanner.list_buckets()
        print(f"[*] Found {len(owned)} owned buckets")
        for name in owned:
            result = scanner.scan_bucket(name)
            all_results.append(result)
    elif not args.bucket and not args.enum:
        print("[!] No access keys provided and no target bucket specified.")
        print("[!] Use --access-key/--secret-key for authenticated scan, or --bucket for unauthenticated probe.")
        parser.print_help()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n[+] Results saved to {args.output}")

    print("\n[*] Scan complete.")


if __name__ == "__main__":
    main()
