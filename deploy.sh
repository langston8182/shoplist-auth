#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT="${1:-localhost}"      # localhost | preprod | prod
FUNCTION_NAME="${FUNCTION_NAME:?FUNCTION_NAME not set}"
REGION="${REGION:-eu-west-1}"

echo "==> Deploying ENV=$ENVIRONMENT for function=$FUNCTION_NAME in $REGION"

# -- Helpers ---------------------------------------------------------------
merge_and_update_env() {
  # $1 = target env value (localhost | preprod | prod)
  local target="$1"
  local existing updated tmpfile
  existing=$(aws lambda get-function-configuration \
    --function-name "$FUNCTION_NAME" \
    --region "$REGION" \
    --query 'Environment.Variables' \
    --output json)

  # Coalesce null -> {} and compact to one line
  updated=$(printf '%s' "${existing:-null}" \
    | jq -c --arg env "$target" '(. // {}) + {ENVIRONMENT: $env}')

  # Utiliser file:// pour --environment
  tmpfile=$(mktemp)
  printf '{"Variables":%s}\n' "$updated" > "$tmpfile"

  aws lambda update-function-configuration \
    --function-name "$FUNCTION_NAME" \
    --region "$REGION" \
    --environment "file://$tmpfile" \
    >/dev/null

  rm -f "$tmpfile"

  # Attendre la fin de l’update avant publish-version
  aws lambda wait function-updated \
    --function-name "$FUNCTION_NAME" \
    --region "$REGION"
}

publish_version() {
  # $1 = description suffix
  local desc="Release $(date +%Y-%m-%dT%H:%M:%S) $1"
  local out ver
  out=$(aws lambda publish-version \
    --region "$REGION" \
    --function-name "$FUNCTION_NAME" \
    --description "$desc")
  ver=$(echo "$out" | python -c 'import sys,json;print(json.load(sys.stdin)["Version"])')
  echo "$ver"
}

upsert_alias() {
  # $1 = alias name (preprod|prod), $2 = version
  local alias_name="$1" ver="$2"
  echo "Pointing alias '$alias_name' to version $ver..."
  set +e
  local out
  out=$(aws lambda update-alias \
    --region "$REGION" \
    --function-name "$FUNCTION_NAME" \
    --name "$alias_name" \
    --function-version "$ver" 2>&1)
  local rc=$?
  set -e

  if [ $rc -eq 0 ]; then
    echo "Alias '$alias_name' updated."
    return 0
  fi

  if echo "$out" | grep -q "ResourceNotFoundException"; then
    aws lambda create-alias \
      --region "$REGION" \
      --function-name "$FUNCTION_NAME" \
      --name "$alias_name" \
      --function-version "$ver" \
      >/dev/null
    echo "Alias '$alias_name' created."
  else
    echo "Failed to update alias '$alias_name':"
    echo "$out"
    exit $rc
  fi
}

# -- Flow ------------------------------------------------------------------

if [[ "$ENVIRONMENT" == "localhost" ]]; then
  echo "Setting \$LATEST to ENVIRONMENT=localhost..."
  merge_and_update_env "localhost"
  echo "Done: \$LATEST has ENVIRONMENT=localhost."
  exit 0
fi

# preprod/prod: set ENV temporarily, publish a version, move alias, restore localhost
echo "Temporarily setting ENVIRONMENT=$ENVIRONMENT on \$LATEST..."
merge_and_update_env "$ENVIRONMENT"

NEW_VERSION=$(publish_version "ENV=$ENVIRONMENT")
echo "Published version: $NEW_VERSION"

upsert_alias "$ENVIRONMENT" "$NEW_VERSION"

echo "Restoring \$LATEST back to ENVIRONMENT=localhost..."
merge_and_update_env "localhost"

echo "Done: alias '$ENVIRONMENT' -> version $NEW_VERSION; \$LATEST restored to ENVIRONMENT=localhost."