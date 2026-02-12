# image-upload-transit Design

A CLI tool for uploading images and short videos to TransitApp's GCS buckets, returning short public URLs.

## CLI Interface

```
image-upload-transit [OPTIONS] <file1> [file2] [file3] ...

Options:
  --staging, -s     Upload to staging environment (default: prod)
  --help, -h        Show help message
  --version, -v     Show version
```

Output: one URL per line in input order. Errors to stderr.

### First-run behavior

1. Check for `op` (1Password CLI) - if missing, print install instructions
2. Authenticate with 1Password if needed
3. Fetch service account key from Shared vault, cache locally

## File Validation

**Limits:**
- Images: 25 MB max
- Videos: 100 MB max

**Allowed formats:**
- Images: jpg, jpeg, png, gif, webp, avif, heic, bmp, tiff, tif, svg
- Videos: mp4, mov, webm

**Validation order:**
1. File exists and is readable
2. File size within limits
3. MIME type detection (mimetypes + magic bytes)
4. Extension in allowed list

## URL Structure

- Production: `img.transitapp.com/<8-char-uuid>.<ext>`
- Staging: `img-staging.transitapp.com/<8-char-uuid>.<ext>`

ID is first 8 characters of UUID v4. Original filename not exposed.

## Infrastructure

### GCS Buckets (in boxwood-complex-208616)

- `transit-uploads-prod`
- `transit-uploads-staging`

Configuration:
- Location: US-CENTRAL1
- Storage class: Standard
- Public read (allUsers objectViewer)
- Lifecycle: delete after 3 years

### Service Account

- Name: `image-upload-transit`
- Permissions: `roles/storage.objectCreator` on both buckets

### 1Password

Item "image-upload-transit Service Account" in Shared vault with notes:
```
Service account for image-upload-transit CLI tool.

GitHub: https://github.com/TransitApp/image-upload-transit

Install:
  brew tap transitapp/image-upload-transit https://github.com/TransitApp/image-upload-transit
  brew install image-upload-transit

Usage:
  image-upload-transit screenshot.png
  image-upload-transit --staging debug.png
```

### Cloudflare (transitapp.com)

DNS records:
- `img` CNAME → `c.storage.googleapis.com` (proxied)
- `img-staging` CNAME → `c.storage.googleapis.com` (proxied)

Page rules rewrite to appropriate bucket, cache everything.

## Repository

**GitHub:** TransitApp/image-upload-transit (public)

```
image-upload-transit/
├── image_upload_transit.py
├── Formula/
│   └── image-upload-transit.rb
├── .github/workflows/
│   ├── ci.yml
│   └── release.yml
├── README.md
├── LICENSE (MIT)
└── tests/
    └── test_upload.py
```

## CI/CD

**CI (on PR/push):**
- Python linting
- Run tests with mock GCS

**Release (on version change in main):**
1. Extract VERSION from code
2. Compare to latest tag
3. If new: create tag, GitHub release, update formula SHA256

## Installation

```bash
brew tap transitapp/image-upload-transit https://github.com/TransitApp/image-upload-transit
brew install image-upload-transit
```

## Error Handling

Clear, actionable messages:
```
✗ file.png: File does not exist
✗ video.mp4: File too large (150 MB). Maximum is 100 MB for videos
✗ doc.pdf: Unsupported file type. Allowed: jpg, png, ...
✗ 1Password CLI not found. Install with: brew install 1password-cli
```

Exit codes:
- 0: All uploads succeeded
- 1: One or more uploads failed
- 2: Configuration/auth error

## Security

- Credentials cached at `~/.config/image-upload-transit/credentials.json` (chmod 600)
- No shell injection (subprocess with lists)
- MIME type validation
- Random non-guessable URLs
