#!/bin/sh
set -eu

archive=
checksum=
bundle=
repository=
allow_unsigned=false
install_root=${XDG_DATA_HOME:-"$HOME/.local/share"}/company-mesh
bin_dir=${XDG_BIN_HOME:-"$HOME/.local/bin"}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --archive) archive=$2; shift 2 ;;
    --checksum) checksum=$2; shift 2 ;;
    --bundle) bundle=$2; shift 2 ;;
    --repository) repository=$2; shift 2 ;;
    --allow-unsigned) allow_unsigned=true; shift ;;
    --install-root) install_root=$2; shift 2 ;;
    --bin-dir) bin_dir=$2; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$archive" ] || [ -z "$checksum" ]; then
  echo "Usage: install.sh --archive FILE --checksum FILE [--bundle FILE --repository OWNER/REPO]" >&2
  exit 2
fi

archive=$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")
checksum=$(cd "$(dirname "$checksum")" && pwd)/$(basename "$checksum")
if command -v shasum >/dev/null 2>&1; then
  (cd "$(dirname "$archive")" && shasum -a 256 -c "$checksum")
else
  (cd "$(dirname "$archive")" && sha256sum -c "$checksum")
fi

if [ -z "$bundle" ] && [ "$allow_unsigned" != true ]; then
  echo "A Sigstore bundle is required. Use --allow-unsigned only for a trusted local build." >&2
  exit 1
fi

if [ -n "$bundle" ]; then
  if [ -z "$repository" ] || ! command -v cosign >/dev/null 2>&1; then
    echo "A signed bundle requires --repository OWNER/REPO and cosign." >&2
    exit 1
  fi
  cosign verify-blob "$archive" \
    --bundle "$bundle" \
    --certificate-identity-regexp "^https://github.com/$repository/.github/workflows/release.yml@refs/tags/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
fi

extract_dir=$(mktemp -d "${TMPDIR:-/tmp}/company-mesh-install.XXXXXX")
trap 'trash "$extract_dir" 2>/dev/null || rm -r "$extract_dir"' EXIT INT TERM
if tar -tzf "$archive" | awk 'BEGIN { bad=0 } /^\// || /(^|\/)\.\.($|\/)/ { bad=1 } END { exit bad ? 0 : 1 }'; then
  echo "The archive contains an unsafe path." >&2
  exit 1
fi
tar -C "$extract_dir" -xzf "$archive"
package_dir=$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d -name 'company-mesh-*' -print -quit)
if [ -z "$package_dir" ]; then
  echo "The archive does not contain a Company Mesh package." >&2
  exit 1
fi

mkdir -p "$install_root" "$bin_dir"
install -m 0755 "$package_dir/bin/companyd" "$install_root/companyd"
install -m 0755 "$package_dir/bin/company-mesh" "$install_root/company-mesh"
install -m 0644 "$package_dir/lib/company-mesh/company-mcp.mjs" "$install_root/company-mcp.mjs"
ln -sfn "$install_root/companyd" "$bin_dir/companyd"
ln -sfn "$install_root/company-mesh" "$bin_dir/company-mesh"

echo "Installed Company Mesh in $install_root"
echo "Run: company-mesh setup --organization YOUR_ORG --node-name YOUR_NODE --agent-id agent:YOUR_NAME --permissions observer"
