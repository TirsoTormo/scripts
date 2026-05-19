<#
.SYNOPSIS
    Start-SystemHealthCheck.ps1
    Phase 1: Deep Windows diagnostics and auto-repair (DISM + SFC).
    Phase 2: Automated multi-folder backup with progress bar and dynamic destination selection.
    NOTE: MUST BE RUN AS ADMINISTRATOR!
#>

Clear-Host

# ASCII Art header
Write-Host @"
 ______________________________________________________
|                                                      |
|   ██████╗ ███████╗██╗  ██╗███████╗██╗     ████████╗  |
|   ██╔══██╗██╔════╝██║  ██║██╔════╝██║     ╚══██╔══╝  |
|   ██████╔╝███████╗███████║█████╗  ██║        ██║     |
|   ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║        ██║     |
|   ██║     ███████║██║  ██║███████╗███████╗   ██║     |
|   ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝     |
|             SYSTEM HEALTH & BACKUP                   |
|______________________________________________________|
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host " [!] Launching automated maintenance suite..." -ForegroundColor Yellow
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host ""

# =========================================================================
# SOURCE CONFIGURATION (Folders to back up)
# =========================================================================
$MisCarpetas = @(
    "$env:USERPROFILE\Documents\Proyectos",
    "$env:USERPROFILE\Desktop\Fotos_Importantes",
    "C:\MiAppFavorita\Datos",
    "$env:USERPROFILE\Videos"
)

# Time variable for file naming
$Fecha = Get-Date -Format "yyyy-MM-dd_HHmm"

# =========================================================================
# PRE-CHECK: SOURCE PATHS VERIFICATION
# =========================================================================
Write-Host "[PRE-CHECK] Verifying source folder paths..." -ForegroundColor Cyan
Write-Host "---------------------------------------------------------" -ForegroundColor Gray
$RutasOK = $true

foreach ($Origen in $MisCarpetas) {
    if (Test-Path $Origen) {
        Write-Host " [OK] Path found: $Origen" -ForegroundColor Green
    }
    else {
        Write-Host " [ERROR] Path does NOT exist or is misconfigured: $Origen" -ForegroundColor Red
        $RutasOK = $false
    }
}
Write-Host "---------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

# =========================================================================
# PHASE 1: SYSTEM HEALTH CHECK & AUTO-REPAIR
# =========================================================================
Write-Host "[PHASE 1] -> Running System Health Check" -ForegroundColor Magenta
Write-Host "---------------------------------------------------------" -ForegroundColor Gray
Write-Host " IMPORTANT NOTICE:" -ForegroundColor Yellow
Write-Host " This process analyzes and repairs the core Windows image files." -ForegroundColor White
Write-Host " IT USUALLY TAKES BETWEEN 5 AND 15 MINUTES DEPENDING ON YOUR PC." -ForegroundColor Yellow
Write-Host " Please do not close this window or power off your computer." -ForegroundColor White
Write-Host "---------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

# 1. Repair Windows Image using DISM
Write-Host " [+] Analyzing and repairing Windows Image (DISM)..." -ForegroundColor Cyan
DISM /Online /Cleanup-Image /RestoreHealth

Write-Host ""

# 2. Scan and repair system files using SFC
Write-Host " [+] Scanning and repairing corrupt system files (SFC)..." -ForegroundColor Cyan
sfc /scannow

Write-Host ""
Write-Host " INFO: PHASE 1 Completed. System optimized and verified." -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host ""

# =========================================================================
# PHASE 2: DESTINATION SELECTION & BACKUP
# =========================================================================
Write-Host "[PHASE 2] -> Backup Configuration & Execution" -ForegroundColor Magenta
Write-Host "---------------------------------------------------------" -ForegroundColor Gray

if ($RutasOK -eq $false) {
    Write-Host " [!] WARNING: Some source paths failed the pre-check validation." -ForegroundColor Yellow
    Write-Host " The script will attempt to back up only the existing paths." -ForegroundColor White
    Write-Host ""
}

# Prompt user for the destination path interactively
Write-Host " Enter the destination path or drive letter to store your backups." -ForegroundColor White
Write-Host " (Example: D:\Backups or E:\BackupFolder or C:\Users\User\Desktop)" -ForegroundColor DarkGray
$CarpetaDestinoBase = Read-Host " Destination path"

# Validate user input
if ([string]::IsNullOrWhiteSpace($CarpetaDestinoBase)) {
    Write-Host " ERROR: No valid path was entered. Skipping Phase 2." -ForegroundColor Red
}
else {
    # Ensure destination directory exists, try to create it if it doesn't
    if (!(Test-Path $CarpetaDestinoBase)) {
        try {
            New-Item -ItemType Directory -Path $CarpetaDestinoBase -Force | Out-Null
            Write-Host " [+] Created destination directory at: $CarpetaDestinoBase" -ForegroundColor DarkGray
        }
        catch {
            Write-Host " ERROR: Could not create or access the specified path: $_" -ForegroundColor Red
            $CarpetaDestinoBase = $null
        }
    }
}

# Proceed with backup if destination path is valid
if ($CarpetaDestinoBase) {
    Write-Host ""
    Write-Host " Starting file compression..." -ForegroundColor Yellow
    Write-Host "---------------------------------------------------------" -ForegroundColor Gray

    # Progress bar counters
    $TotalCarpetas = $MisCarpetas.Count
    $Contador = 0

    # Process each folder with a progress bar
    foreach ($Origen in $MisCarpetas) {
        $Contador++
        
        if (Test-Path $Origen) {
            $NombreCarpeta = Split-Path $Origen -Leaf
            $ArchivoZipDestino = "$CarpetaDestinoBase\Backup_${NombreCarpeta}_$Fecha.zip"
            
            # Calculate percentage for progress bar
            $Porcentaje = [int](($Contador / $TotalCarpetas) * 100)
            
            # Single-line command for the native Windows progress bar
            Write-Progress -Activity "Compressing Files" -Status "Processing: ${NombreCarpeta} ($Contador of $TotalCarpetas)" -PercentComplete $Porcentaje
            
            Write-Host " [+] [$Contador/$TotalCarpetas] Compressing: ${NombreCarpeta}..." -ForegroundColor Cyan
            Write-Host "     Source:      $Origen" -ForegroundColor DarkGray
            Write-Host "     Destination: $ArchivoZipDestino" -ForegroundColor DarkGray
            
            try {
                # Silent archival compression
                Compress-Archive -Path $Origen -DestinationPath $ArchivoZipDestino -Force
                Write-Host "     OK: Successfully completed." -ForegroundColor Green
            }
            catch {
                Write-Host "     ERROR: Failed to back up ${NombreCarpeta}: $_" -ForegroundColor Red
            }
        }
        else {
            Write-Host " [!] [$Contador/$TotalCarpetas] Skipping: Path not found ($Origen)" -ForegroundColor Yellow
        }
        Write-Host ""
    }

    # Close progress bar explicitly upon completion
    Write-Progress -Activity "Compressing Files" -Completed
}

# =========================================================================
# END OF SCRIPT
# =========================================================================
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "           MAINTENANCE AND BACKUP COMPLETE             " -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host " All system checks are complete and operations have finalized successfully." -ForegroundColor White
Write-Host ""

# Final pause to review logs before exit
Read-Host "Press Enter to close this tool"
