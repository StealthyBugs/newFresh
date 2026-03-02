#!/usr/bin/env bash
# upload-sagemaker.sh
# Compresses SageMaker source files and uploads them as a GitHub release
# to StealthyBugs/analyzeforvulns.
#
# Usage:
#   export GH_TOKEN="your_github_token"
#   ./upload-sagemaker.sh

set -euo pipefail

REPO="StealthyBugs/analyzeforvulns"
ARCHIVE="/tmp/sagemaker-source.tar.xz"
TAG="sagemaker-snapshot"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "${GH_TOKEN:-}" ]; then
  echo "Error: GH_TOKEN environment variable is not set."
  echo "Usage: GH_TOKEN=your_token ./upload-sagemaker.sh"
  exit 1
fi

AUTH_HEADER="Authorization: token ${GH_TOKEN}"
API="https://api.github.com"

echo "==> Compressing SageMaker source files..."
tar -cJf "$ARCHIVE" --exclude='.git' --exclude='upload-sagemaker.sh' -C "$SCRIPT_DIR" .
echo "    Archive created: $(ls -lh "$ARCHIVE" | awk '{print $5}') $ARCHIVE"

# Check if repo is empty and initialize if needed
REPO_SIZE=$(curl -sf -H "$AUTH_HEADER" "$API/repos/$REPO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('size',0))")

if [ "$REPO_SIZE" -eq 0 ]; then
  echo "==> Repository is empty. Creating initial commit..."
  curl -sf -X PUT -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    "$API/repos/$REPO/contents/README.md" \
    -d "{\"message\":\"Initial commit\",\"content\":\"$(echo '# analyzeforvulns' | base64 -w0)\"}" \
    > /dev/null
  echo "    Initial commit created."
fi

# Delete existing release/tag if present
EXISTING=$(curl -sf -H "$AUTH_HEADER" "$API/repos/$REPO/releases/tags/$TAG" 2>/dev/null || true)
if [ -n "$EXISTING" ]; then
  RELEASE_ID=$(echo "$EXISTING" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
  echo "==> Deleting existing release ($RELEASE_ID)..."
  curl -sf -X DELETE -H "$AUTH_HEADER" "$API/repos/$REPO/releases/$RELEASE_ID" > /dev/null
  curl -sf -X DELETE -H "$AUTH_HEADER" "$API/repos/$REPO/git/refs/tags/$TAG" > /dev/null 2>&1 || true
fi

# Create the release
echo "==> Creating release '$TAG'..."
RELEASE_RESPONSE=$(curl -sf -X POST -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  "$API/repos/$REPO/releases" \
  -d "{\"tag_name\":\"$TAG\",\"name\":\"SageMaker source snapshot\",\"body\":\"Compressed archive of SageMaker source files.\"}")

UPLOAD_URL=$(echo "$RELEASE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['upload_url'].replace('{?name,label}',''))")
echo "    Release created."

# Upload the archive
echo "==> Uploading archive..."
curl -sf -X POST -H "$AUTH_HEADER" \
  -H "Content-Type: application/x-xz" \
  "${UPLOAD_URL}?name=sagemaker-source.tar.xz" \
  --data-binary "@$ARCHIVE" > /dev/null

echo "==> Done! Release available at: https://github.com/$REPO/releases/tag/$TAG"
