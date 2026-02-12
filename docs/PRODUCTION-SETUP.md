# Production Setup

After applying production terraform, complete these steps:

## 1. Create service account key

```bash
gcloud iam service-accounts keys create /tmp/prod-key.json \
  --iam-account=image-upload-transit@boxwood-complex-208616.iam.gserviceaccount.com
```

## 2. Store in 1Password

```bash
CLIENT_EMAIL=$(jq -r '.client_email' /tmp/prod-key.json)
TOKEN_URI=$(jq -r '.token_uri' /tmp/prod-key.json)
PRIVATE_KEY=$(jq -r '.private_key' /tmp/prod-key.json)

op item create \
  --vault "Shared" \
  --category "API Credential" \
  --title "image-upload-transit Service Account (Production)" \
  --tags "gcp,service-account,cli,production" \
  "client_email[text]=$CLIENT_EMAIL" \
  "token_uri[text]=$TOKEN_URI" \
  "private_key[text]=$PRIVATE_KEY" \
  "notesPlain=Service account for image-upload-transit CLI (production).

GitHub: https://github.com/TransitApp/image-upload-transit

Install:
  brew tap transitapp/image-upload-transit https://github.com/TransitApp/image-upload-transit
  brew install image-upload-transit

Usage:
  image-upload-transit screenshot.png

GCP Project: boxwood-complex-208616
Service Account: image-upload-transit@boxwood-complex-208616.iam.gserviceaccount.com"
```

## 3. Clean up

```bash
rm /tmp/prod-key.json
```

## 4. Test

```bash
image-upload-transit ~/Desktop/test.png
# Should return: https://img.transitapp.com/<id>.png
```
