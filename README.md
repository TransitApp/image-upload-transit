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
