#!/usr/bin/env bash
set -euo pipefail

# Load .env
[ -f .env ] && source .env

# Replace these with the fileIDs your POST /files returned:
FILE1=${FILE1:-$(jq -r .fileID <<<"$POST1_RESPONSE")}
FILE2=${FILE2:-$(jq -r .fileID <<<"$POST2_RESPONSE")}

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

# Now pull them back down:
echo "=== Download and diff ==="
curl -s http://localhost:8080/files/$FILE1 -H "X-Owner-ID: user1" > out1.txt
curl -s http://localhost:8080/files/$FILE2 -H "X-Owner-ID: user2" > out2.txt

echo "diff user1 → out1.txt"
if ! diff -u test_files/user1.txt out1.txt; then
  echo "ERROR: user1 download mismatch" >&2
  exit 1
fi

echo "diff user2 → out2.txt"
if ! diff -u test_files/user1.txt out2.txt; then
  echo "ERROR: user2 download mismatch" >&2
  exit 1
fi

echo "✅ All checks passed!"
