#!/usr/bin/env bash
# Configure immutable v* release tags that require all main CI checks to pass.
# Run once with a repository-admin token after the required check names exist.
# Usage: GH_TOKEN=... ./scripts/setup-tag-protection.sh
set -euo pipefail

: "${GH_TOKEN:?Set GH_TOKEN to a repository-admin token}"
REPO="${REPO:-pohoc/crypto-sm}"

PAYLOAD="$(python3 - <<'PY'
import json

checks = [
    "full-ci / Composer validation",
    "full-ci / Static analysis and style",
    "full-ci / Composer audit",
]
for php_version in ("8.2", "8.3", "8.4", "8.5"):
    for dependencies in ("lowest", "highest"):
        checks.append(f"full-ci / Test (PHP {php_version} / {dependencies})")

print(json.dumps({
    "name": "release-tags-require-ci",
    "target": "tag",
    "enforcement": "active",
    "bypass_actors": [],
    "conditions": {
        "ref_name": {"include": ["refs/tags/v*"], "exclude": []},
    },
    "rules": [
        {
            "type": "required_status_checks",
            "parameters": {
                "strict_required_status_checks_policy": False,
                "required_status_checks": [{"context": check} for check in checks],
            },
        },
        {"type": "deletion", "parameters": {}},
        {"type": "update", "parameters": {}},
    ],
}))
PY
)"

API="https://api.github.com/repos/$REPO/rulesets"
EXISTING_ID="$(curl -fsS \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H 'Accept: application/vnd.github+json' \
    "$API" \
  | python3 -c 'import json,sys; print(next((str(item["id"]) for item in json.load(sys.stdin) if item.get("name") == "release-tags-require-ci"), ""))')"

if [[ -n "$EXISTING_ID" ]]; then
  RESPONSE="$(curl -sS -w $'\n%{http_code}' -X PUT \
      -H "Authorization: Bearer $GH_TOKEN" \
      -H 'Accept: application/vnd.github+json' \
      -H 'Content-Type: application/json' \
      "$API/$EXISTING_ID" \
      -d "$PAYLOAD")"
else
  RESPONSE="$(curl -sS -w $'\n%{http_code}' -X POST \
      -H "Authorization: Bearer $GH_TOKEN" \
      -H 'Accept: application/vnd.github+json' \
      -H 'Content-Type: application/json' \
      "$API" \
      -d "$PAYLOAD")"
fi

HTTP_STATUS="${RESPONSE##*$'\n'}"
RESPONSE_BODY="${RESPONSE%$'\n'*}"
if [[ "$HTTP_STATUS" != 200 && "$HTTP_STATUS" != 201 ]]; then
  printf 'Failed to configure tag ruleset (HTTP %s):\n%s\n' "$HTTP_STATUS" "$RESPONSE_BODY" >&2
  exit 1
fi

RULESET_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<< "$RESPONSE_BODY")"
printf 'Tag protection is active (ruleset id=%s).\n' "$RULESET_ID"
