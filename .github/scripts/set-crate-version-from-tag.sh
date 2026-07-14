#!/usr/bin/env bash
# Bump the version of the supportfile Rust crates from the pushed git tag.
#
# Used by .github/workflows/rust-python-packages.yml when the workflow is
# triggered by a tag of the form `v<semver>` (e.g. `v0.1.2`). The leading
# `v` is stripped and the resulting version is written to all three crate
# Cargo.toml files so the published artifacts match the tag:
#
#   - rca-tool/lib/supportfile_core    (published to crates.io as `supportfile`)
#   - rca-tool/lib/supportfile_py      (built as a Python wheel)
#   - rca-tool/lib/supportfile_wasm    (used by the Leptos front-end build)
#   - rca-tool/lib/supportfile_mcp     (published to crates.io as `supportfile_mcp`)
#
# After updating Cargo.toml files, the corresponding Cargo.lock entries
# are refreshed so subsequent `cargo --locked` invocations stay green.
#
# Environment:
#   GITHUB_REF_NAME — tag name as provided by GitHub Actions (e.g. `v0.1.2`).
#                      Falls back to parsing `GITHUB_REF` if unset.

set -euo pipefail

ref_name="${GITHUB_REF_NAME:-}"
if [[ -z "$ref_name" && -n "${GITHUB_REF:-}" ]]; then
    ref_name="${GITHUB_REF#refs/tags/}"
fi

if [[ -z "$ref_name" ]]; then
    echo "ERROR: neither GITHUB_REF_NAME nor GITHUB_REF is set" >&2
    exit 1
fi

if [[ ! "$ref_name" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-].+)?$ ]]; then
    echo "ERROR: tag '$ref_name' does not look like a semver tag (expected vX.Y.Z)" >&2
    exit 1
fi

version="${ref_name#v}"
echo "Setting supportfile crate versions to $version (from tag $ref_name)"

# Repo root is the working directory when invoked by Actions; resolve relative
# to this script so it can also be run locally from anywhere.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

declare -a crate_dirs=(
    "$repo_root/rca-tool/lib/supportfile_core"
    "$repo_root/rca-tool/lib/supportfile_py"
    "$repo_root/rca-tool/lib/supportfile_wasm"
    "$repo_root/rca-tool/lib/supportfile_mcp"
    "$repo_root/rca-tool/lib/supportfile_pii_anonymizer"
)

for dir in "${crate_dirs[@]}"; do
    toml="$dir/Cargo.toml"
    if [[ ! -f "$toml" ]]; then
        echo "ERROR: $toml not found" >&2
        exit 1
    fi
    # Replace the FIRST `version = "..."` line only (package version, not
    # dependency versions). Cargo convention places it in the [package]
    # table at the top of the file. Use perl (identical on Linux and macOS)
    # instead of sed, whose in-place flag and `0,/re/` address differ between
    # GNU and BSD.
    perl -0777 -i -pe 's/^version[ \t]*=[ \t]*".*"/version = "'"$version"'"/m' "$toml"
    echo "  updated $toml"
done

# Keep internal path-dependency version requirements in lockstep with the bumped
# package version. `cargo publish` requires path deps to carry a version, and it
# must match the just-published `supportfile_pii_anonymizer` version. Applies to
# the crates that depend on it via path (supportfile_core is the published one;
# supportfile_wasm carries no version pin, so it is skipped here).
for consumer in supportfile_core; do
    ctoml="$repo_root/rca-tool/lib/$consumer/Cargo.toml"
    if grep -q 'supportfile_pii_anonymizer[[:space:]]*=' "$ctoml"; then
        perl -i -pe 's/(supportfile_pii_anonymizer[ \t]*=[ \t]*\{[^}]*version[ \t]*=[ \t]*")[^"]*(")/${1}'"$version"'${2}/' "$ctoml"
        echo "  synced $consumer dependency version -> $version"
    fi
done

# Refresh Cargo.lock entries for the renamed packages so `cargo --locked`
# continues to work in subsequent build/test/publish steps. Each crate has
# its own lockfile; path dependencies don't hit the network.
#
# NOTE: this deliberately avoids bash associative arrays (`declare -A`). The
# GitHub macOS runners ship bash 3.2, which does not support them — the map
# would silently collapse, the loop would skip every crate, and the stale
# lockfiles would then break the subsequent `cargo build --locked`. A `case`
# statement is portable back to bash 3.2.
for dir in \
    "$repo_root/rca-tool/lib/supportfile_core" \
    "$repo_root/rca-tool/lib/supportfile_py" \
    "$repo_root/rca-tool/lib/supportfile_wasm" \
    "$repo_root/rca-tool/lib/supportfile_mcp" \
    "$repo_root/rca-tool/lib/supportfile_pii_anonymizer"; do
    case "$dir" in
        */supportfile_core) pkgs="supportfile supportfile_pii_anonymizer" ;;
        */supportfile_py) pkgs="supportfile_py supportfile" ;;
        */supportfile_wasm) pkgs="supportfile-wasm supportfile supportfile_pii_anonymizer" ;;
        */supportfile_mcp) pkgs="supportfile_mcp" ;;
        */supportfile_pii_anonymizer) pkgs="supportfile_pii_anonymizer" ;;
        *) pkgs="" ;;
    esac
    [[ -n "$pkgs" ]] || continue
    if [[ -f "$dir/Cargo.lock" ]]; then
        args=()
        for p in $pkgs; do
            args+=(-p "$p")
        done
        echo "  refreshing $dir/Cargo.lock for: $pkgs"
        (cd "$dir" && cargo update "${args[@]}" --offline 2>/dev/null) \
            || (cd "$dir" && cargo update "${args[@]}")
    fi
done

echo "Done."
