#!/usr/bin/env bash
# Build the Nitro Enclave Image File (EIF) for pomade-signer and print the
# resulting PCR measurements.
#
# Usage (run from the repo root on an EC2 instance with nitro-cli installed):
#
#   ./scripts/build-eif.sh [--output path/to/output.eif]
#
# The PCR0/PCR1/PCR2 values printed at the end are the measurements you should
# pin in your KMS key policy so that only this exact build can decrypt secrets:
#
#   "StringEquals": {
#     "kms:RecipientAttestation:PCR0": "<PCR0>",
#     "kms:RecipientAttestation:PCR1": "<PCR1>",
#     "kms:RecipientAttestation:PCR2": "<PCR2>"
#   }
#
# PCR0 = hash of the enclave image (EIF)
# PCR1 = hash of the Linux kernel and bootstrap
# PCR2 = hash of the application (everything in the image after the kernel)
#
# Re-run this script after every code change and update your KMS policy with
# the new values before deploying.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_EIF="${1:-${REPO_ROOT}/pomade-signer.eif}"

# Resolve the --output flag if passed explicitly
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT_EIF="$2"; shift 2 ;;
    *) shift ;;
  esac
done

echo "==> Building Docker image for Nitro Enclave..."
docker build \
  --file "${REPO_ROOT}/pomade-signer/Dockerfile.nitro" \
  --tag pomade-signer-nitro:latest \
  "${REPO_ROOT}"

echo ""
echo "==> Building EIF from Docker image..."
nitro-cli build-enclave \
  --docker-uri pomade-signer-nitro:latest \
  --output-file "${OUTPUT_EIF}" \
  | tee /tmp/nitro-build-output.json

echo ""
echo "==> EIF written to: ${OUTPUT_EIF}"
echo ""

# Extract and display PCR values from the build output
PCR0=$(jq -r '.Measurements.PCR0' /tmp/nitro-build-output.json)
PCR1=$(jq -r '.Measurements.PCR1' /tmp/nitro-build-output.json)
PCR2=$(jq -r '.Measurements.PCR2' /tmp/nitro-build-output.json)

echo "==> PCR Measurements (pin these in your KMS key policy):"
echo ""
echo "  PCR0 (image):   ${PCR0}"
echo "  PCR1 (kernel):  ${PCR1}"
echo "  PCR2 (app):     ${PCR2}"
echo ""
echo "==> KMS condition block:"
cat <<EOF
{
  "StringEquals": {
    "kms:RecipientAttestation:PCR0": "${PCR0}",
    "kms:RecipientAttestation:PCR1": "${PCR1}",
    "kms:RecipientAttestation:PCR2": "${PCR2}"
  }
}
EOF
