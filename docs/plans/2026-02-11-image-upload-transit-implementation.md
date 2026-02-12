# image-upload-transit Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a CLI tool for uploading images/videos to GCS with short transitapp.com URLs.

**Architecture:** Python CLI fetches credentials from 1Password, validates files, uploads to GCS via REST API, returns short URLs. Cloudflare Workers proxy requests from img.transitapp.com to GCS buckets.

**Tech Stack:** Python 3 (stdlib only), Terraform, Cloudflare Workers, GCS, 1Password CLI, GitHub Actions

---

## Task 1: Create GitHub Repository

**Step 1: Create the repo**

```bash
gh repo create TransitApp/image-upload-transit --public --description "CLI tool for uploading images and videos to Transit's CDN"
```

**Step 2: Set remote and push existing commit**

```bash
cd /Users/gcamp/Dev/image-upload-transit
git remote add origin git@github.com:TransitApp/image-upload-transit.git
git branch -M main
git push -u origin main
```

**Step 3: Verify**

Run: `gh repo view TransitApp/image-upload-transit`

---

## Task 2: Create GCS Buckets (Terraform)

**Files:**
- Create: `/Users/gcamp/Dev/infra/terraform/roots/shared-infra/production/image-upload-transit.tf`
- Create: `/Users/gcamp/Dev/infra/terraform/roots/shared-infra/staging/image-upload-transit.tf`

**Step 1: Create production terraform file**

File: `/Users/gcamp/Dev/infra/terraform/roots/shared-infra/production/image-upload-transit.tf`

```hcl
### image-upload-transit buckets and service account
### https://github.com/TransitApp/image-upload-transit

resource "google_storage_bucket" "transit_uploads_prod" {
  name          = "transit-uploads-prod"
  storage_class = "STANDARD"
  location      = "US-CENTRAL1"

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 1095 # 3 years
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    env  = "production"
    name = "transit-uploads-prod"
  }
}

resource "google_storage_bucket_iam_member" "transit_uploads_prod_public" {
  bucket = google_storage_bucket.transit_uploads_prod.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_service_account" "image_upload_transit" {
  account_id   = "image-upload-transit"
  display_name = "Service account for image-upload-transit CLI"
}

resource "google_storage_bucket_iam_member" "transit_uploads_prod_writer" {
  bucket = google_storage_bucket.transit_uploads_prod.name
  role   = "roles/storage.objectCreator"
  member = google_service_account.image_upload_transit.member
}

resource "google_storage_bucket_iam_member" "transit_uploads_staging_writer" {
  bucket = "transit-uploads-staging"
  role   = "roles/storage.objectCreator"
  member = google_service_account.image_upload_transit.member
}
```

**Step 2: Create staging terraform file**

File: `/Users/gcamp/Dev/infra/terraform/roots/shared-infra/staging/image-upload-transit.tf`

```hcl
### image-upload-transit staging bucket
### https://github.com/TransitApp/image-upload-transit

resource "google_storage_bucket" "transit_uploads_staging" {
  name          = "transit-uploads-staging"
  storage_class = "STANDARD"
  location      = "US-CENTRAL1"

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age = 1095 # 3 years
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    env  = "staging"
    name = "transit-uploads-staging"
  }
}

resource "google_storage_bucket_iam_member" "transit_uploads_staging_public" {
  bucket = google_storage_bucket.transit_uploads_staging.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
```

**Step 3: Run terraform plan for both environments**

```bash
cd /Users/gcamp/Dev/infra/terraform/roots/shared-infra/production
terraform plan -out=plan.tfplan

cd /Users/gcamp/Dev/infra/terraform/roots/shared-infra/staging
terraform plan -out=plan.tfplan
```

**Step 4: Wait for user approval, then apply**

STOP: Show plan output to user. Only proceed with `terraform apply plan.tfplan` after explicit approval.

---

## Task 3: Create Cloudflare Worker for URL Proxying

**Files:**
- Create: `/Users/gcamp/Dev/infra/terraform/roots/cloudflare/transitapp.com/workers.tf`

**Step 1: Create workers terraform file**

File: `/Users/gcamp/Dev/infra/terraform/roots/cloudflare/transitapp.com/workers.tf`

```hcl
### image-upload-transit URL proxying
### Proxies img.transitapp.com and img-staging.transitapp.com to GCS buckets

resource "cloudflare_worker_script" "img_proxy" {
  account_id = "YOUR_ACCOUNT_ID" # TODO: Get from existing config
  name       = "img-proxy"
  content    = <<-EOF
    addEventListener('fetch', event => {
      event.respondWith(handleRequest(event.request))
    })

    async function handleRequest(request) {
      const url = new URL(request.url)
      const hostname = url.hostname

      let bucket
      if (hostname === 'img.transitapp.com') {
        bucket = 'transit-uploads-prod'
      } else if (hostname === 'img-staging.transitapp.com') {
        bucket = 'transit-uploads-staging'
      } else {
        return new Response('Not found', { status: 404 })
      }

      const gcsUrl = `https://storage.googleapis.com/${bucket}${url.pathname}`

      const response = await fetch(gcsUrl, {
        method: request.method,
        headers: request.headers
      })

      const newResponse = new Response(response.body, response)
      newResponse.headers.set('Cache-Control', 'public, max-age=31536000')
      return newResponse
    }
  EOF
}

resource "cloudflare_worker_route" "img_prod" {
  zone_id     = local.zone_id
  pattern     = "img.transitapp.com/*"
  script_name = cloudflare_worker_script.img_proxy.name
}

resource "cloudflare_worker_route" "img_staging" {
  zone_id     = local.zone_id
  pattern     = "img-staging.transitapp.com/*"
  script_name = cloudflare_worker_script.img_proxy.name
}
```

**Step 2: Add DNS records for img subdomains**

Add to `/Users/gcamp/Dev/infra/terraform/roots/cloudflare/transitapp.com/records-a.tf`:

```hcl
resource "cloudflare_record" "img" {
  zone_id = local.zone_id
  name    = "img"
  proxied = true
  type    = "A"
  value   = "192.0.2.1" # Dummy IP, worker handles traffic
}

resource "cloudflare_record" "img_staging" {
  zone_id = local.zone_id
  name    = "img-staging"
  proxied = true
  type    = "A"
  value   = "192.0.2.1" # Dummy IP, worker handles traffic
}
```

**Step 3: Run terraform plan**

```bash
cd /Users/gcamp/Dev/infra/terraform/roots/cloudflare/transitapp.com
terraform plan -out=plan.tfplan
```

**Step 4: Wait for user approval**

STOP: Show plan to user, apply only after explicit approval.

---

## Task 4: Create Service Account Key and Store in 1Password

**Step 1: Generate service account key (after terraform apply)**

```bash
gcloud iam service-accounts keys create /tmp/image-upload-transit-key.json \
  --iam-account=image-upload-transit@boxwood-complex-208616.iam.gserviceaccount.com
```

**Step 2: Create 1Password item**

```bash
op item create \
  --vault "Shared" \
  --category "API Credential" \
  --title "image-upload-transit Service Account" \
  --tags "gcp,service-account,cli" \
  "credential[file]=/tmp/image-upload-transit-key.json" \
  "notesPlain=Service account for image-upload-transit CLI tool.

GitHub: https://github.com/TransitApp/image-upload-transit

Install:
  brew tap transitapp/image-upload-transit https://github.com/TransitApp/image-upload-transit
  brew install image-upload-transit

Usage:
  image-upload-transit screenshot.png
  image-upload-transit --staging debug.png"
```

**Step 3: Delete local key file**

```bash
rm /tmp/image-upload-transit-key.json
```

**Step 4: Verify**

```bash
op item get "image-upload-transit Service Account" --vault Shared
```

---

## Task 5: Write Python CLI - Core Structure

**Files:**
- Create: `/Users/gcamp/Dev/image-upload-transit/image_upload_transit.py`

**Step 1: Create the main script with argument parsing and version**

```python
#!/usr/bin/env python3
"""CLI tool for uploading images and videos to Transit's CDN."""

import argparse
import json
import mimetypes
import os
import subprocess
import sys
import urllib.request
import urllib.error
import uuid
from pathlib import Path

VERSION = "1.0.0"

CONFIG_DIR = Path.home() / ".config" / "image-upload-transit"
CREDENTIALS_FILE = CONFIG_DIR / "credentials.json"

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".heic", ".bmp", ".tiff", ".tif", ".svg"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".webm"}
ALL_EXTENSIONS = IMAGE_EXTENSIONS | VIDEO_EXTENSIONS

MAX_IMAGE_SIZE = 25 * 1024 * 1024  # 25 MB
MAX_VIDEO_SIZE = 100 * 1024 * 1024  # 100 MB

BUCKET_PROD = "transit-uploads-prod"
BUCKET_STAGING = "transit-uploads-staging"
URL_PROD = "https://img.transitapp.com"
URL_STAGING = "https://img-staging.transitapp.com"

OP_VAULT = "Shared"
OP_ITEM = "image-upload-transit Service Account"


def error(msg: str) -> None:
    print(f"\033[91m✗\033[0m {msg}", file=sys.stderr)


def success(msg: str) -> None:
    print(f"\033[92m✓\033[0m {msg}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Upload images and videos to Transit's CDN",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s screenshot.png
  %(prog)s photo1.jpg photo2.png video.mp4
  %(prog)s --staging debug-screenshot.png
""",
    )
    parser.add_argument("files", nargs="+", help="Files to upload")
    parser.add_argument("-s", "--staging", action="store_true", help="Upload to staging environment")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--refresh-credentials", action="store_true", help="Re-fetch credentials from 1Password")

    args = parser.parse_args()

    try:
        credentials = get_credentials(force_refresh=args.refresh_credentials)
    except CredentialsError as e:
        error(str(e))
        return 2

    bucket = BUCKET_STAGING if args.staging else BUCKET_PROD
    base_url = URL_STAGING if args.staging else URL_PROD

    had_error = False
    for filepath in args.files:
        try:
            url = upload_file(filepath, bucket, base_url, credentials)
            print(url)
        except UploadError as e:
            error(f"{filepath}: {e}")
            had_error = True

    return 1 if had_error else 0


if __name__ == "__main__":
    sys.exit(main())
```

**Step 2: Verify syntax**

```bash
python3 -m py_compile /Users/gcamp/Dev/image-upload-transit/image_upload_transit.py
```

---

## Task 6: Write Python CLI - Credentials Management

**Files:**
- Modify: `/Users/gcamp/Dev/image-upload-transit/image_upload_transit.py`

**Step 1: Add credentials error class and 1Password functions**

Add after the constants, before `error()`:

```python
class CredentialsError(Exception):
    pass


class UploadError(Exception):
    pass


def check_op_cli() -> None:
    """Check if 1Password CLI is installed."""
    try:
        subprocess.run(["op", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        raise CredentialsError(
            "1Password CLI not found. Install with: brew install 1password-cli\n"
            "Then sign in with: op signin"
        )


def get_credentials(force_refresh: bool = False) -> dict:
    """Get GCS credentials from cache or 1Password."""
    if not force_refresh and CREDENTIALS_FILE.exists():
        try:
            with open(CREDENTIALS_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass  # Fall through to fetch from 1Password

    check_op_cli()

    try:
        result = subprocess.run(
            ["op", "item", "get", OP_ITEM, "--vault", OP_VAULT, "--fields", "credential", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        if "not signed in" in e.stderr.lower() or "sign in" in e.stderr.lower():
            raise CredentialsError("Not signed in to 1Password. Run: op signin")
        if "not found" in e.stderr.lower():
            raise CredentialsError(f"1Password item '{OP_ITEM}' not found in vault '{OP_VAULT}'")
        raise CredentialsError(f"Failed to fetch credentials from 1Password: {e.stderr}")

    try:
        field_data = json.loads(result.stdout)
        cred_value = field_data.get("value", "")
        credentials = json.loads(cred_value)
    except (json.JSONDecodeError, KeyError) as e:
        raise CredentialsError(f"Failed to parse credentials from 1Password: {e}")

    # Cache credentials
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(credentials, f)
    os.chmod(CREDENTIALS_FILE, 0o600)

    return credentials
```

**Step 2: Verify syntax**

```bash
python3 -m py_compile /Users/gcamp/Dev/image-upload-transit/image_upload_transit.py
```

---

## Task 7: Write Python CLI - File Validation

**Files:**
- Modify: `/Users/gcamp/Dev/image-upload-transit/image_upload_transit.py`

**Step 1: Add validation function**

Add after `get_credentials()`:

```python
def validate_file(filepath: str) -> tuple[Path, str]:
    """Validate file exists, size, and type. Returns (path, extension)."""
    path = Path(filepath)

    if not path.exists():
        raise UploadError("File does not exist")

    if not path.is_file():
        raise UploadError("Not a file")

    ext = path.suffix.lower()
    if ext not in ALL_EXTENSIONS:
        allowed = ", ".join(sorted(e.lstrip(".") for e in ALL_EXTENSIONS))
        raise UploadError(f"Unsupported file type. Allowed: {allowed}")

    size = path.stat().st_size
    is_video = ext in VIDEO_EXTENSIONS
    max_size = MAX_VIDEO_SIZE if is_video else MAX_IMAGE_SIZE
    file_type = "videos" if is_video else "images"

    if size > max_size:
        size_mb = size / (1024 * 1024)
        max_mb = max_size / (1024 * 1024)
        raise UploadError(f"File too large ({size_mb:.1f} MB). Maximum is {max_mb:.0f} MB for {file_type}")

    if size == 0:
        raise UploadError("File is empty")

    return path, ext
```

**Step 2: Verify syntax**

```bash
python3 -m py_compile /Users/gcamp/Dev/image-upload-transit/image_upload_transit.py
```

---

## Task 8: Write Python CLI - GCS Upload

**Files:**
- Modify: `/Users/gcamp/Dev/image-upload-transit/image_upload_transit.py`

**Step 1: Add OAuth token generation**

Add after `validate_file()`:

```python
def get_access_token(credentials: dict) -> str:
    """Get OAuth2 access token from service account credentials."""
    import base64
    import hashlib
    import hmac
    import time

    # JWT header and claims
    header = {"alg": "RS256", "typ": "JWT"}
    now = int(time.time())
    claims = {
        "iss": credentials["client_email"],
        "scope": "https://www.googleapis.com/auth/devstorage.read_write",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
    }

    def b64encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    header_b64 = b64encode(json.dumps(header).encode())
    claims_b64 = b64encode(json.dumps(claims).encode())
    signing_input = f"{header_b64}.{claims_b64}"

    # Sign with RSA-SHA256 using openssl (available on macOS)
    private_key = credentials["private_key"]
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", "/dev/stdin"],
        input=private_key.encode() + b"\n" + signing_input.encode(),
        capture_output=True,
    )

    # Actually we need a different approach - openssl expects key file
    # Let's use a temp file approach
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        f.write(private_key)
        key_file = f.name

    try:
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_file],
            input=signing_input.encode(),
            capture_output=True,
            check=True,
        )
        signature = b64encode(proc.stdout)
    finally:
        os.unlink(key_file)

    jwt = f"{signing_input}.{signature}"

    # Exchange JWT for access token
    data = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": jwt,
    }).encode()

    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    try:
        with urllib.request.urlopen(req) as resp:
            token_data = json.loads(resp.read())
            return token_data["access_token"]
    except urllib.error.HTTPError as e:
        raise UploadError(f"Failed to get access token: {e.read().decode()}")
```

**Step 2: Add upload function**

Add after `get_access_token()`:

```python
def upload_file(filepath: str, bucket: str, base_url: str, credentials: dict) -> str:
    """Upload file to GCS and return public URL."""
    path, ext = validate_file(filepath)

    # Generate unique ID
    file_id = uuid.uuid4().hex[:8]
    object_name = f"{file_id}{ext}"

    # Get access token
    token = get_access_token(credentials)

    # Read file
    with open(path, "rb") as f:
        file_data = f.read()

    # Determine content type
    content_type, _ = mimetypes.guess_type(str(path))
    if content_type is None:
        content_type = "application/octet-stream"

    # Upload to GCS
    upload_url = f"https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o?uploadType=media&name={object_name}"

    req = urllib.request.Request(
        upload_url,
        data=file_data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            resp.read()  # Consume response
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        raise UploadError(f"Upload failed: {error_body}")

    return f"{base_url}/{object_name}"
```

**Step 3: Add urllib.parse import at top**

Add to imports at top of file:

```python
import urllib.parse
```

**Step 4: Verify syntax**

```bash
python3 -m py_compile /Users/gcamp/Dev/image-upload-transit/image_upload_transit.py
```

---

## Task 9: Add Tests

**Files:**
- Create: `/Users/gcamp/Dev/image-upload-transit/tests/test_upload.py`

**Step 1: Create test file**

```python
#!/usr/bin/env python3
"""Tests for image_upload_transit."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
import image_upload_transit as iut


class TestValidation(unittest.TestCase):
    def test_validate_nonexistent_file(self):
        with self.assertRaises(iut.UploadError) as ctx:
            iut.validate_file("/nonexistent/file.png")
        self.assertIn("does not exist", str(ctx.exception))

    def test_validate_unsupported_type(self):
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"test")
            path = f.name
        try:
            with self.assertRaises(iut.UploadError) as ctx:
                iut.validate_file(path)
            self.assertIn("Unsupported file type", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_validate_empty_file(self):
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            path = f.name
        try:
            with self.assertRaises(iut.UploadError) as ctx:
                iut.validate_file(path)
            self.assertIn("empty", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_validate_valid_image(self):
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(b"fake png data")
            path = f.name
        try:
            result_path, ext = iut.validate_file(path)
            self.assertEqual(ext, ".png")
        finally:
            os.unlink(path)

    def test_validate_video_extensions(self):
        for ext in [".mp4", ".mov", ".webm"]:
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as f:
                f.write(b"fake video data")
                path = f.name
            try:
                result_path, result_ext = iut.validate_file(path)
                self.assertEqual(result_ext, ext)
            finally:
                os.unlink(path)


class TestCredentials(unittest.TestCase):
    @patch("subprocess.run")
    def test_check_op_cli_missing(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        with self.assertRaises(iut.CredentialsError) as ctx:
            iut.check_op_cli()
        self.assertIn("1Password CLI not found", str(ctx.exception))


class TestArgParsing(unittest.TestCase):
    def test_version_in_code(self):
        self.assertIsInstance(iut.VERSION, str)
        self.assertRegex(iut.VERSION, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
```

**Step 2: Run tests**

```bash
cd /Users/gcamp/Dev/image-upload-transit
python3 -m pytest tests/ -v || python3 -m unittest tests/test_upload.py -v
```

---

## Task 10: Create CI Workflow

**Files:**
- Create: `/Users/gcamp/Dev/image-upload-transit/.github/workflows/ci.yml`

**Step 1: Create CI workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint-and-test:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install ruff pytest

      - name: Lint with ruff
        run: ruff check image_upload_transit.py

      - name: Run tests
        run: python -m pytest tests/ -v
```

---

## Task 11: Create Release Workflow

**Files:**
- Create: `/Users/gcamp/Dev/image-upload-transit/.github/workflows/release.yml`

**Step 1: Create release workflow**

```yaml
name: Release

on:
  push:
    branches: [main]
    paths:
      - "image_upload_transit.py"

jobs:
  check-version:
    runs-on: ubuntu-latest
    outputs:
      should_release: ${{ steps.check.outputs.should_release }}
      version: ${{ steps.check.outputs.version }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Check for version change
        id: check
        run: |
          VERSION=$(grep -E "^VERSION = " image_upload_transit.py | sed 's/VERSION = "\(.*\)"/\1/')
          echo "version=$VERSION" >> $GITHUB_OUTPUT

          if git tag | grep -q "^v$VERSION$"; then
            echo "should_release=false" >> $GITHUB_OUTPUT
          else
            echo "should_release=true" >> $GITHUB_OUTPUT
          fi

  release:
    needs: check-version
    if: needs.check-version.outputs.should_release == 'true'
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - name: Create tag
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git tag -a "v${{ needs.check-version.outputs.version }}" -m "Release v${{ needs.check-version.outputs.version }}"
          git push origin "v${{ needs.check-version.outputs.version }}"

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          tag_name: v${{ needs.check-version.outputs.version }}
          name: v${{ needs.check-version.outputs.version }}
          generate_release_notes: true

      - name: Update Homebrew formula
        run: |
          VERSION="${{ needs.check-version.outputs.version }}"
          SHA256=$(sha256sum image_upload_transit.py | cut -d' ' -f1)

          cat > Formula/image-upload-transit.rb << EOF
          class ImageUploadTransit < Formula
            desc "CLI tool for uploading images and videos to Transit's CDN"
            homepage "https://github.com/TransitApp/image-upload-transit"
            url "https://raw.githubusercontent.com/TransitApp/image-upload-transit/v${VERSION}/image_upload_transit.py"
            sha256 "${SHA256}"
            license "MIT"

            depends_on "python@3.11"
            depends_on "1password-cli"

            def install
              bin.install "image_upload_transit.py" => "image-upload-transit"
            end

            test do
              system "#{bin}/image-upload-transit", "--version"
            end
          end
          EOF

          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add Formula/image-upload-transit.rb
          git commit -m "Update formula for v${VERSION}" || true
          git push
```

---

## Task 12: Create Homebrew Formula (Initial)

**Files:**
- Create: `/Users/gcamp/Dev/image-upload-transit/Formula/image-upload-transit.rb`

**Step 1: Create initial formula**

```ruby
class ImageUploadTransit < Formula
  desc "CLI tool for uploading images and videos to Transit's CDN"
  homepage "https://github.com/TransitApp/image-upload-transit"
  url "https://raw.githubusercontent.com/TransitApp/image-upload-transit/v1.0.0/image_upload_transit.py"
  sha256 "PLACEHOLDER"
  license "MIT"

  depends_on "python@3.11"
  depends_on "1password-cli"

  def install
    bin.install "image_upload_transit.py" => "image-upload-transit"
  end

  test do
    system "#{bin}/image-upload-transit", "--version"
  end
end
```

---

## Task 13: Create README and LICENSE

**Files:**
- Create: `/Users/gcamp/Dev/image-upload-transit/README.md`
- Create: `/Users/gcamp/Dev/image-upload-transit/LICENSE`

**Step 1: Create README**

```markdown
# image-upload-transit

CLI tool for uploading images and videos to Transit's CDN.

## Installation

```bash
brew tap transitapp/image-upload-transit https://github.com/TransitApp/image-upload-transit
brew install image-upload-transit
```

## Usage

```bash
# Upload single file
image-upload-transit screenshot.png

# Upload multiple files
image-upload-transit photo1.jpg photo2.png video.mp4

# Upload to staging
image-upload-transit --staging debug-screenshot.png
```

## Supported Formats

**Images (max 25 MB):** jpg, jpeg, png, gif, webp, avif, heic, bmp, tiff, svg

**Videos (max 100 MB):** mp4, mov, webm

## First Run

On first run, you'll need:

1. [1Password CLI](https://developer.1password.com/docs/cli/) installed and signed in
2. Access to the Transit 1Password Shared vault

The tool will fetch credentials from 1Password and cache them locally.

## Development

```bash
# Run tests
python3 -m pytest tests/ -v

# Lint
ruff check image_upload_transit.py
```
```

**Step 2: Create LICENSE**

```text
MIT License

Copyright (c) 2026 Transit Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Task 14: Final Commit and Push

**Step 1: Commit all files**

```bash
cd /Users/gcamp/Dev/image-upload-transit
git add .
git commit -m "Initial implementation of image-upload-transit CLI

- Python CLI with 1Password integration for credentials
- File validation (size, type)
- GCS upload with OAuth2
- CI/CD with GitHub Actions
- Homebrew formula for easy installation

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

**Step 2: Push to GitHub**

```bash
git push origin main
```

---

## Task 15: Commit and Apply Terraform (Infra Repo)

**Step 1: Commit terraform changes**

```bash
cd /Users/gcamp/Dev/infra
git checkout -b image-upload-transit
git add terraform/roots/shared-infra/production/image-upload-transit.tf
git add terraform/roots/shared-infra/staging/image-upload-transit.tf
git add terraform/roots/cloudflare/transitapp.com/workers.tf
git add terraform/roots/cloudflare/transitapp.com/records-a.tf
git commit -m "Add infrastructure for image-upload-transit

- GCS buckets for prod and staging
- Service account with objectCreator role
- Cloudflare Worker for URL proxying
- DNS records for img and img-staging subdomains

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

**Step 2: Push and create PR**

```bash
git push -u origin image-upload-transit
gh pr create --title "Add infrastructure for image-upload-transit" --body "Adds GCS buckets, service account, and Cloudflare config for the image-upload-transit CLI tool.

See: https://github.com/TransitApp/image-upload-transit"
```

---

## Execution Order

1. **Task 1**: Create GitHub repo (required first)
2. **Tasks 5-8**: Write Python CLI (can be done in parallel with Task 2-3)
3. **Task 2**: Create GCS buckets terraform (needs approval)
4. **Task 3**: Create Cloudflare workers terraform (needs approval)
5. **Task 4**: Create service account key (after Task 2 is applied)
6. **Task 9-13**: Tests, CI/CD, README, LICENSE
7. **Task 14**: Commit and push CLI code
8. **Task 15**: Commit and push infra changes

**Dependencies:**
- Task 4 depends on Task 2 being applied
- Task 14 depends on Task 1
- Task 15 depends on Tasks 2-3
