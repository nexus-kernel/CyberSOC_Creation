#!/usr/bin/env bash
# Explicit official-source alternative; never auto-fall back after a denied download.
set -euo pipefail
: "${XDG_DATA_HOME:?Run through .codex/setup.sh}"
for executable in git dotnet pwsh; do
  command -v "$executable" >/dev/null || { echo "Missing source-build prerequisite: $executable" >&2; exit 1; }
done
pester_commit=81e59ad383579f957bcc3e0faf4085461b189032 # official Pester tag 5.9.1
pester_source=$(mktemp -d "$PWD/.dev-cache/pester-source.XXXXXX")
trap 'rm -rf -- "$pester_source"' EXIT
export DOTNET_CLI_HOME="$PWD/.dev-cache/dotnet"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false
export NUGET_PACKAGES="$PWD/.dev-cache/nuget"
git -C "$pester_source" init -q
git -C "$pester_source" fetch --depth 1 https://github.com/pester/Pester.git "$pester_commit"
git -C "$pester_source" checkout -q --detach FETCH_HEAD
test "$(git -C "$pester_source" rev-parse HEAD)" = "$pester_commit"
# Official CONTRIBUTING.md/build.ps1; locked NuGet restore, no patched sources.
pwsh -NoProfile -File "$pester_source/build.ps1" -Clean -Inline -LockedRestore
pester_destination="$XDG_DATA_HOME/powershell/Modules/Pester/5.9.1"
mkdir -p "$pester_destination"
cp -R "$pester_source/bin/." "$pester_destination/"
printf '%s\n' "Pester 5.9.1 built from https://github.com/pester/Pester/commit/$pester_commit" > "$PWD/.dev-cache/pester-provenance.txt"
