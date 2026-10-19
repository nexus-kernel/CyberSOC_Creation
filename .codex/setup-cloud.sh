#!/usr/bin/env bash
# Reproducible Linux x64 validation setup. No credentials or system-wide writes.
set -euo pipefail
# Route only to this checkout (or an explicitly selected CyberSOC checkout).
cybersoc_root="${CYBERSOC_REPO_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
cd -- "$cybersoc_root"
case "$(git remote get-url origin)" in
  https://github.com/nexus-kernel/CyberSOC_Creation.git|git@github.com:nexus-kernel/CyberSOC_Creation.git) ;;
  *) echo 'Refusing setup outside nexus-kernel/CyberSOC_Creation.' >&2; exit 1 ;;
esac
test "$(uname -s)/$(uname -m)" = Linux/x86_64 || { echo 'This bootstrap requires Linux x64.' >&2; exit 1; }
for executable in node npm python3 gh git curl tar; do
  command -v "$executable" >/dev/null || { echo "Missing prerequisite: $executable" >&2; exit 1; }
done
local_tools="$PWD/.dev-cache/tools"
mkdir -p "$local_tools"
export PATH="$local_tools/pwsh:$local_tools/dotnet:$PATH"
if ! command -v pwsh >/dev/null; then
  mkdir -p "$local_tools/pwsh"
  curl --fail --silent --show-error --location https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell-7.4.6-linux-x64.tar.gz -o "$local_tools/powershell.tar.gz"
  tar xzf "$local_tools/powershell.tar.gz" -C "$local_tools/pwsh"
  chmod +x "$local_tools/pwsh/pwsh"
fi
if ! command -v dotnet >/dev/null; then
  installer_commit=e5cf1dd2d1540ed05ac84f8eb8c5cdec2807621e
  installer_source=$(mktemp -d "$local_tools/dotnet-installer.XXXXXX")
  trap 'rm -rf -- "$installer_source"' EXIT
  git -C "$installer_source" init -q
  git -C "$installer_source" fetch --depth 1 https://github.com/dotnet/install-scripts.git "$installer_commit"
  git -C "$installer_source" checkout -q --detach FETCH_HEAD
  test "$(git -C "$installer_source" rev-parse HEAD)" = "$installer_commit"
  bash "$installer_source/src/dotnet-install.sh" --version 8.0.408 --install-dir "$local_tools/dotnet" --no-path
fi
# This file is self-contained so its contents can be pasted into the saved
# environment setup before these repository changes have been published.
node -e 'if (Number(process.versions.node.split(".")[0]) < 18) process.exit(1)'
python3 -c 'import sys; assert sys.version_info >= (3, 10)'
export npm_config_cache="$PWD/.dev-cache/npm"
export PIP_CACHE_DIR="$PWD/.dev-cache/pip"
export XDG_CACHE_HOME="$PWD/.dev-cache/cache"
export XDG_CONFIG_HOME="$PWD/.dev-cache/config"
export XDG_DATA_HOME="$PWD/.dev-cache/data"
export DOTNET_CLI_HOME="$PWD/.dev-cache/dotnet"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false
export NUGET_PACKAGES="$PWD/.dev-cache/nuget"
mkdir -p "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"
npm ci
python3 -m venv .venv
.venv/bin/python -m pip install PyYAML==6.0.3
pester_commit=81e59ad383579f957bcc3e0faf4085461b189032
pester_source=$(mktemp -d "$PWD/.dev-cache/pester-source.XXXXXX")
trap 'rm -rf -- "$pester_source"; if [ -n "${installer_source:-}" ]; then rm -rf -- "$installer_source"; fi' EXIT
git -C "$pester_source" init -q
git -C "$pester_source" fetch --depth 1 https://github.com/pester/Pester.git "$pester_commit"
git -C "$pester_source" checkout -q --detach FETCH_HEAD
test "$(git -C "$pester_source" rev-parse HEAD)" = "$pester_commit"
pwsh -NoProfile -File "$pester_source/build.ps1" -Clean -Inline -LockedRestore
pester_destination="$XDG_DATA_HOME/powershell/Modules/Pester/5.9.1"
mkdir -p "$pester_destination"
cp -R "$pester_source/bin/." "$pester_destination/"
printf '%s\n' "Pester 5.9.1 built from https://github.com/pester/Pester/commit/$pester_commit" > "$PWD/.dev-cache/pester-provenance.txt"
pwsh -NoProfile -Command 'Import-Module Pester -RequiredVersion 5.9.1 -ErrorAction Stop; Get-Module Pester | Select-Object Name,Version,Path'
