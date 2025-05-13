#!/usr/bin/env bash
set -euo pipefail

# Load .env
[ -f .env ] && source .env

echo "=== features ==="
psql "$DSDE_POSTGRES_DSN" --no-align --field-separator ' | ' \
     -c "SELECT encode(fea_hash,'hex') AS fea_hash, length(dek_shared) AS dek_len FROM features;"
echo

echo "=== chunks count ==="
psql "$DSDE_POSTGRES_DSN" --no-align --field-separator ' | ' \
     -c "SELECT is_common, count(*) FROM chunks GROUP BY is_common;"
echo

echo "=== file_chunks ==="
psql "$DSDE_POSTGRES_DSN" --no-align --field-separator ' | ' \
     -c "SELECT file_id, seq, chunk_hash FROM file_chunks ORDER BY file_id, seq;"
echo

echo "=== S3 object count ==="
aws --endpoint-url="$AWS_ENDPOINT_URL" --no-cli-pager s3api list-objects \
    --bucket "$DSDE_S3_BUCKET" \
    --query 'length(Contents[])' --output text
echo

echo "=== S3 object keys ==="
aws --endpoint-url="$AWS_ENDPOINT_URL" --no-cli-pager s3api list-objects \
    --bucket "$DSDE_S3_BUCKET" \
    --query 'Contents[].Key' --output text
echo
