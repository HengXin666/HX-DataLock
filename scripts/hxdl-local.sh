#!/usr/bin/env sh
set -u

KEYRING_PATH="${HXDL_KEYRING:-keyring.hxdl.json}"

say() {
  printf '%s\n' "$*"
}

ask() {
  prompt="$1"
  default_value="${2:-}"
  if [ -n "$default_value" ]; then
    printf '%s [%s]: ' "$prompt" "$default_value"
  else
    printf '%s: ' "$prompt"
  fi
  IFS= read -r answer
  if [ -z "$answer" ]; then
    printf '%s' "$default_value"
  else
    printf '%s' "$answer"
  fi
}

need_uv() {
  if ! command -v uv >/dev/null 2>&1; then
    say "error: uv is required. Install uv first: https://docs.astral.sh/uv/"
    exit 1
  fi
}

run_hxdl() {
  uv run hxdl "$@"
}

pause() {
  printf 'Press Enter to continue...'
  IFS= read -r _unused || true
}

init_keyring() {
  path="$(ask "Keyring path" "$KEYRING_PATH")"
  say ""
  say "Creating Keyring. Your master password is read locally and is not sent to GitHub."
  run_hxdl init --keyring "$path"
}

send_message() {
  public_key="$(ask "Public Key Document path" "public.hxdl.json")"
  input_path="$(ask "Plaintext input file" "")"
  output_path="$(ask "Encrypted output file" "${input_path}.hxdl.json")"
  if [ -z "$input_path" ] || [ -z "$output_path" ]; then
    say "error: input and output paths are required"
    return 1
  fi
  run_hxdl lock --public "$public_key" --in "$input_path" --out "$output_path"
}

open_message() {
  keyring="$(ask "Keyring path" "$KEYRING_PATH")"
  input_path="$(ask "Encrypted input file" "")"
  output_path="$(ask "Plaintext output file" "")"
  if [ -z "$input_path" ] || [ -z "$output_path" ]; then
    say "error: input and output paths are required"
    return 1
  fi
  say ""
  say "Opening message. Your master password is read locally."
  run_hxdl open --keyring "$keyring" --in "$input_path" --out "$output_path"
}

verify_keyring() {
  keyring="$(ask "Keyring path" "$KEYRING_PATH")"
  run_hxdl verify-keyring --keyring "$keyring"
}

show_public_key() {
  keyring="$(ask "Keyring path" "$KEYRING_PATH")"
  output_path="$(ask "Public Key Document output path" "public.hxdl.json")"
  run_hxdl export-public --keyring "$keyring" --out "$output_path"
}

main_menu() {
  while :; do
    say ""
    say "HX-DataLock local helper"
    say "Keyring default: $KEYRING_PATH"
    say ""
    say "1) Init Keyring"
    say "2) Send / encrypt message"
    say "3) Open / decrypt message"
    say "4) Verify Keyring"
    say "5) Show public Write Key"
    say "0) Exit"
    printf 'Choose: '
    IFS= read -r choice

    case "$choice" in
      1) init_keyring || say "Init failed"; pause ;;
      2) send_message || say "Send failed"; pause ;;
      3) open_message || say "Open failed"; pause ;;
      4) verify_keyring || say "Verify failed"; pause ;;
      5) show_public_key || say "Public key read failed"; pause ;;
      0) exit 0 ;;
      *) say "Unknown choice: $choice" ;;
    esac
  done
}

need_uv
main_menu
