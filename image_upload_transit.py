#!/usr/bin/env python3
"""CLI tool for uploading images/videos to GCS with short transitapp.com URLs."""

import argparse
import base64
import json
import mimetypes
import os
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
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

BUCKET_PROD = "transit-uploads-production"
BUCKET_STAGING = "transit-uploads-staging"
URL_PROD = "https://img.transitapp.com"
URL_STAGING = "https://img-staging.transitapp.com"

OP_VAULT = "Shared"
OP_ITEM = "image-upload-transit Service Account"


class CredentialsError(Exception):
    """Raised when credentials cannot be obtained."""


def error(msg: str) -> None:
    """Print red error message to stderr."""
    print(f"\033[91m\u2717 {msg}\033[0m", file=sys.stderr)


def success(msg: str) -> None:
    """Print green success message to stderr."""
    print(f"\033[92m\u2713 {msg}\033[0m", file=sys.stderr)


def check_op_cli() -> None:
    """Verify 1Password CLI is installed and user is signed in."""
    try:
        subprocess.run(["op", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        raise CredentialsError("1Password CLI not found. Install with: brew install 1password-cli")
    except subprocess.CalledProcessError:
        raise CredentialsError("1Password CLI check failed")

    result = subprocess.run(["op", "account", "list"], capture_output=True)
    if result.returncode != 0 or not result.stdout.strip():
        raise CredentialsError("Not signed in to 1Password. Run: op signin")


def get_credentials(force_refresh: bool = False) -> dict:
    """Fetch credentials from 1Password, caching to file."""
    if not force_refresh and CREDENTIALS_FILE.exists():
        with open(CREDENTIALS_FILE) as f:
            return json.load(f)

    check_op_cli()

    result = subprocess.run(
        ["op", "item", "get", OP_ITEM, "--vault", OP_VAULT, "--format", "json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise CredentialsError(f"Failed to fetch credentials from 1Password: {result.stderr.strip()}")

    item = json.loads(result.stdout)
    credentials = {}

    for field in item.get("fields", []):
        label = field.get("label", "")
        value = field.get("value", "")
        if label == "client_email":
            credentials["client_email"] = value
        elif label == "private_key":
            credentials["private_key"] = value
        elif label == "token_uri":
            credentials["token_uri"] = value

    required = ["client_email", "private_key", "token_uri"]
    missing = [k for k in required if not credentials.get(k)]
    if missing:
        raise CredentialsError(f"Missing credential fields: {', '.join(missing)}")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(credentials, f, indent=2)
    os.chmod(CREDENTIALS_FILE, stat.S_IRUSR | stat.S_IWUSR)  # chmod 600

    return credentials


def validate_file(filepath: str) -> tuple[Path, str]:
    """Validate file exists, is within size limits, and has allowed extension."""
    path = Path(filepath)

    if not path.exists():
        raise ValueError(f"File does not exist: {filepath}")
    if not path.is_file():
        raise ValueError(f"Not a file: {filepath}")

    ext = path.suffix.lower()
    if ext not in ALL_EXTENSIONS:
        raise ValueError(f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALL_EXTENSIONS))}")

    size = path.stat().st_size
    is_video = ext in VIDEO_EXTENSIONS
    max_size = MAX_VIDEO_SIZE if is_video else MAX_IMAGE_SIZE
    file_type = "videos" if is_video else "images"

    if size > max_size:
        size_mb = size / (1024 * 1024)
        max_mb = max_size / (1024 * 1024)
        raise ValueError(f"File too large ({size_mb:.1f} MB). Maximum is {max_mb:.0f} MB for {file_type}")

    return path, ext


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def get_access_token(credentials: dict) -> str:
    """Create JWT, sign with openssl, exchange for OAuth token."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "iss": credentials["client_email"],
        "scope": "https://www.googleapis.com/auth/devstorage.read_write",
        "aud": credentials["token_uri"],
        "iat": now,
        "exp": now + 3600,
    }

    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    unsigned_jwt = f"{header_b64}.{payload_b64}"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as key_file:
        key_file.write(credentials["private_key"])
        key_path = key_file.name

    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_path],
            input=unsigned_jwt.encode(),
            capture_output=True,
        )
        if result.returncode != 0:
            raise CredentialsError(f"Failed to sign JWT: {result.stderr.decode()}")
        signature = _base64url_encode(result.stdout)
    finally:
        os.unlink(key_path)

    signed_jwt = f"{unsigned_jwt}.{signature}"

    data = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": signed_jwt,
    }).encode()

    req = urllib.request.Request(credentials["token_uri"], data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode())
            return result["access_token"]
    except urllib.error.URLError as e:
        raise CredentialsError(f"Failed to obtain access token: {e}")


def upload_file(filepath: str, bucket: str, base_url: str, credentials: dict) -> str:
    """Validate file, generate short ID, upload to GCS, return URL."""
    path, ext = validate_file(filepath)
    short_id = uuid.uuid4().hex[:8]
    object_name = f"{short_id}{ext}"

    access_token = get_access_token(credentials)

    content_type, _ = mimetypes.guess_type(str(path))
    if not content_type:
        content_type = "application/octet-stream"

    with open(path, "rb") as f:
        file_data = f.read()

    upload_url = (
        f"https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o"
        f"?uploadType=media&name={urllib.parse.quote(object_name)}"
    )

    req = urllib.request.Request(upload_url, data=file_data, method="POST")
    req.add_header("Authorization", f"Bearer {access_token}")
    req.add_header("Content-Type", content_type)
    req.add_header("Content-Length", str(len(file_data)))

    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            if response.status not in (200, 201):
                raise ValueError(f"Upload failed with status {response.status}")
    except urllib.error.HTTPError as e:
        raise ValueError(f"Upload failed: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        raise ValueError(f"Upload failed: {e}")

    return f"{base_url}/{object_name}"


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Upload images/videos to GCS with short transitapp.com URLs",
        prog="image-upload-transit",
    )
    parser.add_argument("files", nargs="*", help="Files to upload")
    parser.add_argument("-s", "--staging", action="store_true", help="Use staging environment")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--refresh-credentials", action="store_true", help="Force re-fetch credentials from 1Password")

    args = parser.parse_args()

    if args.refresh_credentials and not args.files:
        try:
            get_credentials(force_refresh=True)
            success("Credentials refreshed")
            return 0
        except CredentialsError as e:
            error(str(e))
            return 2

    if not args.files:
        parser.print_help()
        return 1

    bucket = BUCKET_STAGING if args.staging else BUCKET_PROD
    base_url = URL_STAGING if args.staging else URL_PROD

    try:
        credentials = get_credentials(args.refresh_credentials)
    except CredentialsError as e:
        error(str(e))
        return 2

    exit_code = 0
    for filepath in args.files:
        try:
            url = upload_file(filepath, bucket, base_url, credentials)
            success(f"{filepath} -> {url}")
        except ValueError as e:
            error(str(e))
            exit_code = 1
        except CredentialsError as e:
            error(str(e))
            return 2

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
