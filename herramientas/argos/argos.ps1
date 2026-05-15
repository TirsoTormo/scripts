<#
.SYNOPSIS
ARGOS v1 — Network Intelligence & Packet Factory

.DESCRIPTION
Launches ARGOS interactive menu or passes CLI arguments.
Usage:
  .\argos.ps1              Opens interactive menu
  .\argos.ps1 --scan       Direct CLI command
  .\argos.ps1 --help       Show help
#>

# Add uv to PATH if not already there
if (-not ($env:Path -like "*\.local\bin*")) {
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

uv run python -m argos $args
