# ======================================================================
# WEBHOOK GATEWAY - WINDOWS POWERSHELL SETUP BOOTSTRAPPER (setup.ps1)
# ======================================================================
# This script automates Python detection, venv creation, installing
# requirements, provisioning a secure .env with cryptography keys,
# and booting up the FastAPI ASGI server with 1 single command.
# This script uses 100% pure ASCII characters to prevent encoding bugs.
# Incorporates standard CodeTir Systems automated ASCII layout.
# Featuring automated Python winget provisioners for zero-dependency runs.
# ======================================================================

Clear-Host
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host "   ______          __      ______ _      " -ForegroundColor Yellow
Write-Host "  / ____/___  ____/ /__   /_  __/(_)____ " -ForegroundColor Yellow
Write-Host " / /   / __ \/ __  / _ \   / /  / / ___/ " -ForegroundColor Yellow
Write-Host "/ /___/ /_/ / /_/ /  __/  / /  / / /     " -ForegroundColor Yellow
Write-Host "\____/\____/\__,_/\___/  /_/  /_/_/      " -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host "             CODETIR - AUTOMATED ALL-IN-ONE INSTALLER" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Yellow

# 1. Smart Python Interpreter Detection
$PythonExe = ""

function Find-PythonInterpreter {
    $foundPath = ""
    
    # A. Query Windows Registry for any registered PythonCore installations
    $regPaths = @(
        "HKCU:\Software\Python\PythonCore",
        "HKLM:\SOFTWARE\Python\PythonCore"
    )

    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            $versions = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
            foreach ($ver in $versions) {
                $installPathKey = "$regPath\$($ver.PSChildName)\InstallPath"
                if (Test-Path $installPathKey) {
                    $installPath = Get-ItemProperty -Path $installPathKey -Name "(default)" -ErrorAction SilentlyContinue
                    if ($installPath -and $installPath."(default)") {
                        $exePath = Join-Path $installPath."(default)" "python.exe"
                        if ((Test-Path $exePath) -and ($exePath -notlike "*WindowsApps*")) {
                            $foundPath = $exePath
                            return $foundPath
                        }
                    }
                }
            }
        }
    }

    # B. SCAN Standard user, global, and Anaconda paths directly
    $localPaths = @(
        "C:\Windows\py.exe",
        "$env:USERPROFILE\anaconda3\python.exe",
        "$env:USERPROFILE\miniconda3\python.exe",
        "C:\ProgramData\anaconda3\python.exe",
        "C:\ProgramData\miniconda3\python.exe",
        "C:\Program Files\Python313\python.exe",
        "C:\Program Files\Python312\python.exe",
        "C:\Program Files\Python311\python.exe",
        "C:\Program Files\Python310\python.exe",
        "C:\Program Files (x86)\Python312-32\python.exe",
        "C:\Program Files (x86)\Python311-32\python.exe",
        "$env:USERPROFILE\AppData\Local\Programs\Python\Python313\python.exe",
        "$env:USERPROFILE\AppData\Local\Programs\Python\Python312\python.exe",
        "$env:USERPROFILE\AppData\Local\Programs\Python\Python311\python.exe",
        "$env:USERPROFILE\AppData\Local\Programs\Python\Python310\python.exe",
        "C:\Python313\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe"
    )

    foreach ($path in $localPaths) {
        if (Test-Path $path) {
            $foundPath = $path
            return $foundPath
        }
    }

    # C. Fallback to system command search
    foreach ($cmd in "py", "python", "python3") {
        $cmdObj = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($cmdObj -and $cmdObj.Source -notlike "*WindowsApps*") {
            $testRun = Start-Process -FilePath $cmd -ArgumentList "--version" -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
            if ($testRun -and $testRun.ExitCode -eq 0) {
                $foundPath = $cmd
                return $foundPath
            }
        }
    }

    return ""
}

# Run the detection
$PythonExe = Find-PythonInterpreter

# If Python is not found, offer automatic installation via winget
if ($PythonExe -eq "") {
    Write-Host "[WARNING] Python was not found on your system Registry or common directories." -ForegroundColor Yellow
    $wingetExists = Get-Command winget -ErrorAction SilentlyContinue
    
    if ($wingetExists) {
        Write-Host "Windows Package Manager (winget) detected!" -ForegroundColor Green
        Write-Host "Would you like to install the official Python 3.12 automatically now? (y/n)" -ForegroundColor Cyan
        $installChoice = Read-Host
        
        if ($installChoice -eq "y" -or $installChoice -eq "yes") {
            Write-Host "[INFO] Downloading and installing Python 3.12. Please wait, this may take 1-2 minutes..." -ForegroundColor Cyan
            
            # Execute native winget installation directly in the console session to allow interaction if needed
            winget install --id Python.Python.3.12 --exact --silent --accept-package-agreements --accept-source-agreements
            $exitCode = $LASTEXITCODE
            
            if ($exitCode -eq 0) {
                Write-Host "[INFO] Python 3.12 installed successfully!" -ForegroundColor Green
                Write-Host "[INFO] Refreshing system PATH in current terminal session..." -ForegroundColor Cyan
                
                # Refresh current session PATH environment variables dynamically
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
                
                # Wait a brief moment and retry detection
                Start-Sleep -Seconds 3
                $PythonExe = Find-PythonInterpreter
            } else {
                Write-Error "Winget failed to install Python. Exit Code: $exitCode"
            }
        }
    }
}

if ($PythonExe -eq "") {
    Write-Error "Python was not found on your system Registry, PATH or standard folders. Please install Python 3.10+ manually from python.org."
    exit 1
}

Write-Host "[INFO] Found real Python interpreter: $PythonExe" -ForegroundColor Green

# 2. Setup Virtual Environment (venv)
if (-not (Test-Path "venv")) {
    Write-Host "[INFO] Creating Python virtual environment (venv)..." -ForegroundColor Cyan
    Start-Process -FilePath $PythonExe -ArgumentList "-m venv venv" -NoNewWindow -Wait
}

# Double check that venv was indeed created successfully
if (-not (Test-Path "venv\Scripts\pip.exe")) {
    Write-Error "Failed to initialize the virtual environment folder. Please verify permissions."
    exit 1
}
Write-Host "[INFO] Virtual environment ready." -ForegroundColor Green

# 3. Upgrade Pip & Install Requirements
Write-Host "[INFO] Upgrading pip and installing system requirements..." -ForegroundColor Cyan
Start-Process -FilePath ".\venv\Scripts\pip.exe" -ArgumentList "install --upgrade pip" -NoNewWindow -Wait
Start-Process -FilePath ".\venv\Scripts\pip.exe" -ArgumentList "install -r requirements.txt" -NoNewWindow -Wait
Write-Host "[INFO] All dependencies installed successfully." -ForegroundColor Green

# 4. Auto-Provision secure .env file
if (-not (Test-Path ".env")) {
    Write-Host "[INFO] Auto-provisioning secure .env configuration file..." -ForegroundColor Cyan
    Copy-Item ".env.example" ".env"
    
    # Generate a secure random token using standard .NET cryptography
    $Guid = [Guid]::NewGuid().ToString().Replace("-", "")
    
    # Inject token directly into .env
    (Get-Content ".env") -replace "GATEWAY_TOKEN=my_super_secure_secret_token", "GATEWAY_TOKEN=$Guid" | Set-Content ".env"
    
    Write-Host "[INFO] Created .env with a secure crypt key: $Guid" -ForegroundColor Green
} else {
    Write-Host "[INFO] Active .env configuration found. Retaining." -ForegroundColor Green
}

# 5. Initialize hosts.yaml if missing
if (-not (Test-Path "hosts.yaml")) {
    Write-Host "[INFO] Creating default hosts.yaml registry..." -ForegroundColor Cyan
    $hostsTemplate = 'hosts:
  prod-db-01:
    host: "127.0.0.1"
    port: 22
    username: "admin"'
    Set-Content -Path "hosts.yaml" -Value $hostsTemplate
    Write-Host "[INFO] Created hosts.yaml default registry." -ForegroundColor Green
}

Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host "    INSTALLATION COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host "You can now start the Webhook Gateway. Would you like to run it now? (y/n)" -ForegroundColor Cyan
$runNow = Read-Host

if ($runNow -eq "y" -or $runNow -eq "yes") {
    Write-Host "[INFO] Launching Webhook Gateway ASGI Server on http://localhost:8000..." -ForegroundColor Green
    Write-Host "Press [Ctrl+C] inside terminal to shut down the server safely." -ForegroundColor Gray
    Start-Process -FilePath ".\venv\Scripts\uvicorn.exe" -ArgumentList "app.main:app --host 0.0.0.0 --port 8000 --reload" -NoNewWindow
} else {
    Write-Host "To boot up the server manually, execute:" -ForegroundColor Gray
    Write-Host "   .\venv\Scripts\uvicorn.exe app.main:app --host 0.0.0.0 --port 8000 --reload" -ForegroundColor Cyan
}
