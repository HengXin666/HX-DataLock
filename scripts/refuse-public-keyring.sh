#!/usr/bin/env bash
# Fail when a Keyring document is committed to a public GitHub repository.
# A Keyring holds a password-wrapped Read Key and must stay on private local storage.
set -euo pipefail

echo "A Keyring must stay on private local storage. Never commit it to public GitHub or other public storage. Publish a Public Key Document instead."

keyrings=()
while IFS= read -r -d '' file; do
  if [[ "$file" == *keyring*.hxdl.json ]] || grep -q 'hxdl.keyring.v1' "$file"; then
    keyrings+=("$file")
  fi
done < <(git ls-files -z -- '*.hxdl.json' '*.json')

if [[ ${#keyrings[@]} -eq 0 ]]; then
  echo "No Keyring document is committed."
  exit 0
fi

echo "Committed Keyring documents:"
printf '  %s\n' "${keyrings[@]}"

visibility="${REPO_VISIBILITY:-}"
private="${REPO_PRIVATE:-}"
if [[ "$private" == "true" || "$visibility" == "private" || "$visibility" == "internal" ]]; then
  echo "::warning title=Keyring is committed::This non-public repository contains a Keyring. Do not push it to a public remote. Prefer private local storage and a Public Key Document for senders."
  exit 0
fi

echo "::error title=Public Keyring refused::A Keyring must never be committed to a public GitHub repository."
exit 1
