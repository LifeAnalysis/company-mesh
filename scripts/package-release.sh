#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "Usage: scripts/package-release.sh VERSION TARGET" >&2
  exit 2
fi

release_version=$1
release_target=$2
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
stage_dir=$(mktemp -d "${TMPDIR:-/tmp}/company-mesh-package.XXXXXX")
trap 'trash "$stage_dir" 2>/dev/null || rm -r "$stage_dir"' EXIT INT TERM

cd "$project_root"
npm ci
npm run bundle
cargo build --release --locked

package_root="$stage_dir/company-mesh-$release_version-$release_target"
mkdir -p "$package_root/bin" "$package_root/lib/company-mesh" "$package_root/share/doc/company-mesh"
install -m 0755 target/release/companyd "$package_root/bin/companyd"
install -m 0755 target/release/company-mesh "$package_root/bin/company-mesh"
install -m 0644 build/company-mcp.mjs "$package_root/lib/company-mesh/company-mcp.mjs"
install -m 0644 README.md PLAN.md "$package_root/share/doc/company-mesh/"
install -m 0644 docs/THREAT_MODEL.md docs/PROTOCOL.md docs/SECURITY_AUDIT.md \
  docs/WORKTREE_EXECUTION_PLAN.md "$package_root/share/doc/company-mesh/"

mkdir -p dist
archive="dist/company-mesh-$release_version-$release_target.tar.gz"
tar -C "$stage_dir" -czf "$archive" "company-mesh-$release_version-$release_target"
if command -v shasum >/dev/null 2>&1; then
  (cd dist && shasum -a 256 "$(basename "$archive")" > "$(basename "$archive").sha256")
else
  (cd dist && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
fi
echo "$archive"
