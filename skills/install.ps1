# Install the skills in this folder into every agent skill directory that already exists (Windows):
#   ~\.claude\skills ~\.cursor\skills ~\.codex\skills ~\.agents\skills ~\.grok\skills ~\.gemini\skills
#   ~\.config\opencode\skills ~\.hermes\shared-skills
# Default: a directory junction per skill (no administrator rights needed). -Copy: copies (marked with
# .installed-by-synology-nas-cli). -DryRun: print what would change. -Uninstall: remove what this script
# installed. Existing entries it did not create are left alone.
param([switch]$Copy, [switch]$DryRun, [switch]$Uninstall)
$ErrorActionPreference = "Stop"
$Src = (Resolve-Path $PSScriptRoot).Path
$Mark = ".installed-by-synology-nas-cli"
$Pre = if ($DryRun) { "(dry run) " } else { "" }
$Targets = @(".claude\skills", ".cursor\skills", ".codex\skills", ".agents\skills", ".grok\skills", ".gemini\skills",
             ".config\opencode\skills", ".hermes\shared-skills") | ForEach-Object { Join-Path $HOME $_ }

function Test-Ours($Dest, $Name) {
    if (-not (Test-Path -LiteralPath $Dest)) { return $false }
    $item = Get-Item -LiteralPath $Dest -Force
    if ($item.LinkType) { return ((@($item.Target) -join "") -eq (Join-Path $Src $Name)) }
    return (Test-Path -LiteralPath (Join-Path $Dest $Mark))
}

$found = $false
foreach ($t in $Targets) {
    if (-not (Test-Path -LiteralPath $t -PathType Container)) { continue }
    $found = $true
    foreach ($skill in Get-ChildItem -LiteralPath $Src -Directory) {
        if (-not (Test-Path -LiteralPath (Join-Path $skill.FullName "SKILL.md"))) { continue }
        $dest = Join-Path $t $skill.Name
        if ($Uninstall) {
            if (Test-Ours $dest $skill.Name) {
                if (-not $DryRun) { (Get-Item -LiteralPath $dest -Force).Delete($true) }
                Write-Output "${Pre}removed $dest"
            } elseif (Test-Path -LiteralPath $dest) { Write-Output "${Pre}kept $dest (not installed by this script)" }
            continue
        }
        if (Test-Path -LiteralPath $dest) {
            if (Test-Ours $dest $skill.Name) { if (-not $DryRun) { (Get-Item -LiteralPath $dest -Force).Delete($true) } }
            else { Write-Output "${Pre}skipped $dest (exists, not installed by this script)"; continue }
        }
        if ($Copy) {
            if (-not $DryRun) {
                Copy-Item -LiteralPath $skill.FullName -Destination $dest -Recurse
                New-Item -ItemType File -Path (Join-Path $dest $Mark) | Out-Null
            }
            Write-Output "${Pre}copied $($skill.Name) -> $dest"
        } else {
            if (-not $DryRun) { New-Item -ItemType Junction -Path $dest -Target $skill.FullName | Out-Null }
            Write-Output "${Pre}linked $dest -> $($skill.FullName)"
        }
    }
}
if (-not $found) { Write-Output "no agent skill directory found (looked for: $($Targets -join ', '))" }
