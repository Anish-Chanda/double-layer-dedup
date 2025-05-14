#!/usr/bin/env bash
set -euo pipefail

# Load .env if present
if [ -f .env ]; then
  # shellcheck disable=SC2046
  export $(grep -v '^\s*#' .env | xargs)
fi

: "${AWS_ENDPOINT_URL:?Need to set AWS_ENDPOINT_URL in .env}"
: "${AWS_REGION:?Need to set AWS_REGION in .env}"
: "${AWS_ACCESS_KEY_ID:?Need to set AWS_ACCESS_KEY_ID in .env}"
: "${AWS_SECRET_ACCESS_KEY:?Need to set AWS_SECRET_ACCESS_KEY in .env}"
: "${DSDE_S3_BUCKET:?Need to set DSDE_S3_BUCKET in .env}"
: "${DSDE_KMS_KEY_ID:?Need to set DSDE_KMS_KEY_ID in .env}"

echo "👉 Creating S3 bucket '${DSDE_S3_BUCKET}' in LocalStack..."
aws --endpoint-url="${AWS_ENDPOINT_URL}" \
    s3api create-bucket \
    --bucket "${DSDE_S3_BUCKET}" \
    --region "${AWS_REGION}" 2>/dev/null || \
  echo "   Bucket already exists, skipping."

echo "👉 Checking for existing KMS alias '${DSDE_KMS_KEY_ID}'..."
if aws --endpoint-url="${AWS_ENDPOINT_URL}" kms list-aliases \
      --region "${AWS_REGION}" \
      --query "Aliases[?AliasName=='${DSDE_KMS_KEY_ID}']" \
      --output text | grep -q "${DSDE_KMS_KEY_ID}"; then
  echo "   Alias ${DSDE_KMS_KEY_ID} already exists, skipping."
else
  echo "👉 Creating new KMS key and alias '${DSDE_KMS_KEY_ID}'..."
  KEY_ID=$(aws --endpoint-url="${AWS_ENDPOINT_URL}" kms create-key \
    --description "DSDE local test key" \
    --region "${AWS_REGION}" \
    --query KeyMetadata.KeyId \
    --output text)
  aws --endpoint-url="${AWS_ENDPOINT_URL}" kms create-alias \
    --alias-name "${DSDE_KMS_KEY_ID}" \
    --target-key-id "${KEY_ID}" \
    --region "${AWS_REGION}"
  echo "   Created alias ${DSDE_KMS_KEY_ID} → key ${KEY_ID}"
fi

echo "✅ LocalStack setup complete."
