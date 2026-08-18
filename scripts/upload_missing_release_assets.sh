#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <tag> <repo> <asset-path> [<asset-path> ...]" >&2
  exit 2
fi

tag="$1"
repo="$2"
shift 2

mapfile -t existing_assets < <(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[].name')

declare -A existing_map=()
for asset_name in "${existing_assets[@]}"; do
  existing_map["$asset_name"]=1
done

upload_args=()
for asset_path in "$@"; do
  if [[ ! -f "$asset_path" ]]; then
    echo "missing asset file: $asset_path" >&2
    exit 1
  fi

  asset_name="$(basename "$asset_path")"
  if [[ -n "${existing_map[$asset_name]:-}" ]]; then
    echo "asset already exists on release, skipping: $asset_name"
    continue
  fi

  upload_args+=("$asset_path")
done

if [[ ${#upload_args[@]} -eq 0 ]]; then
  echo "no missing release assets to upload"
  exit 0
fi

gh release upload "$tag" "${upload_args[@]}" --repo "$repo"
