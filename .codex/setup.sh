#!/usr/bin/env bash
# Run during cloud environment setup, with dependencies/network enabled.
set -euo pipefail
cd "$(dirname "$0")/.."
for executable in node npm python3 pwsh gh; do
  command -v "$executable" >/dev/null || { echo "Missing prerequisite: $executable" >&2; exit 1; }
done
node -e 'if (Number(process.versions.node.split(".")[0]) < 18) process.exit(1)'
python3 -c 'import sys; assert sys.version_info >= (3, 10)'
# Keep caches and modules in the writable workspace when HOME is read-only.
export PIP_CACHE_DIR="$PWD/.dev-cache/pip"
export npm_config_cache="$PWD/.dev-cache/npm"
export XDG_CACHE_HOME="$PWD/.dev-cache/cache"
export XDG_CONFIG_HOME="$PWD/.dev-cache/config"
export XDG_DATA_HOME="$PWD/.dev-cache/data"
mkdir -p "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"
npm ci
python3 -m venv .venv
.venv/bin/python -m pip install -r .github/review-gate-requirements.txt
case "${PESTER_INSTALL:-gallery}" in
  gallery)
    pwsh -NoProfile -Command '
      if ($PSVersionTable.PSVersion.Major -lt 7) { throw "PowerShell 7 is required." }
      if (-not (Get-Module -ListAvailable Pester | Where-Object Version -EQ ([version]"5.9.1"))) {
        Install-PSResource -Name Pester -Version 5.9.1 -Repository PSGallery -Scope CurrentUser -TrustRepository -AcceptLicense -ErrorAction Stop
      }
    '
    ;;
  source) bash .codex/install-pester-source.sh ;;
  *) echo "PESTER_INSTALL must be gallery or source" >&2; exit 1 ;;
esac
pwsh -NoProfile -Command 'Import-Module Pester -RequiredVersion 5.9.1 -ErrorAction Stop; Get-Module Pester | Select-Object Name,Version,Path'
printf '%s\n' 'Setup complete. Keep XDG_* pointed at .dev-cache for local PowerShell tests; use .venv/bin/python for gate tests.'
