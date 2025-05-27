# Ensure Admin Rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# ------------------------ Cleanup Functions ------------------------

function Clear-TempFiles {
    Write-Host "Clearing Temp Files..."
    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
}

function Remove-ShadowCopies {
    Write-Host "Removing Shadow Copies..."
    vssadmin delete shadows /all /quiet
}

function Clear-Prefetch {
    Write-Host "Clearing Prefetch Files..."
    Remove-Item "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
}

function Remove-OldUpdates {
    Write-Host "Removing Old Update Files..."
    Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\SoftwareDistribution\DataStore\*" -Recurse -Force -ErrorAction SilentlyContinue
}

function Remove-OldLogs {
    Write-Host "Removing Old Logs..."
    Remove-Item "C:\Windows\Logs\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\System32\winevt\Logs\*" -Recurse -Force -ErrorAction SilentlyContinue
}

function Remove-MemoryDumps {
    Write-Host "Removing Memory Dumps..."
    Remove-Item "C:\Windows\MEMORY.DMP" -Force -ErrorAction SilentlyContinue
}

function Run-DiskCleanup {
    Write-Host "Running Disk Cleanup Tool..."
    Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait
}

function Clear-RecycleBin {
    Write-Host "Clearing Recycle Bin..."
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
}

function Clear-BrowsingCache {
    Write-Host "Clearing Browsing Cache..."
    Remove-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:APPDATA\Mozilla\Firefox\Profiles\*\cache2\*" -Recurse -Force -ErrorAction SilentlyContinue
}

function Clear-WindowsDefenderCache {
    Write-Host "Clearing Windows Defender Cache..."
    Remove-Item "C:\ProgramData\Microsoft\Windows Defender\Scans\*" -Recurse -Force -ErrorAction SilentlyContinue
}

function Clean-Registry {
    Write-Host "Cleaning Registry..."
    $keysToDelete = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bak",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($key in $keysToDelete) {
        if (Test-Path $key) {
            Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Get-ChildItem "HKCU:\Software" | ForEach-Object {
        try {
            $keyPath = $_.PSPath
            if (Test-Path $keyPath) {
                Remove-Item $keyPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Host "Error cleaning registry key: $_"
        }
    }
}

function Remove-OldInstallerFiles {
    Write-Host "Removing Old Installer Files..."
    Remove-Item "C:\Windows\Installer\*" -Recurse -Force -ErrorAction SilentlyContinue
}

function Remove-OldBackupFiles {
    Write-Host "Removing Old Backup Files..."
    vssadmin delete shadows /for=C: /oldest /quiet
}

function Remove-OldEventLogs {
    Write-Host "Clearing Event Logs..."
    wevtutil.exe cl Application
    wevtutil.exe cl Security
    wevtutil.exe cl System
}

function Clear-SuperFetch {
    Write-Host "Clearing SuperFetch and WDI..."
    Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\System32\wdi\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name "SysMain" -ErrorAction SilentlyContinue
}

# ------------------------ New Advanced Options ------------------------

function Clear-ErrorReports {
    Write-Host "Clearing Error Reporting Files..."
    Remove-Item "C:\ProgramData\Microsoft\Windows\WER\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\WER\*" -Recurse -Force -ErrorAction SilentlyContinue
}

function Clear-OldDrivers {
    Write-Host "Removing Old Drivers (PnPUtil)..."
    pnputil /enum-drivers | ForEach-Object {
        if ($_ -match "Published Name : (oem\d+\.inf)") {
            $driver = $Matches[1]
            pnputil /delete-driver $driver /uninstall /force /reboot
        }
    }
}

function Clear-ClipboardHistory {
    Write-Host "Clearing Clipboard History..."
    cmd /c "echo off | clip"
}

function Clear-FontCache {
    Write-Host "Clearing Font Cache..."
    Stop-Service -Name "FontCache" -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:LOCALAPPDATA\FontCache\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name "FontCache" -ErrorAction SilentlyContinue
}

function Clear-WindowsStoreCache {
    Write-Host "Resetting Microsoft Store Cache..."
    wsreset.exe
}

function Clear-DeliveryOptimization {
    Write-Host "Clearing Delivery Optimization Files..."
    Remove-Item "C:\Windows\SoftwareDistribution\DeliveryOptimization\*" -Recurse -Force -ErrorAction SilentlyContinue
}

function Clear-ThumbnailsCache {
    Write-Host "Clearing Thumbnails Cache..."
    Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
}

function Clear-ETLLogs {
    Write-Host "Clearing Event Tracing Logs..."
    Remove-Item "C:\Windows\System32\LogFiles\WMI\*" -Recurse -Force -ErrorAction SilentlyContinue
}

function Clear-DNSCache {
    Write-Host "Flushing DNS Cache..."
    ipconfig /flushdns
}

function Clear-PrintSpool {
    Write-Host "Clearing Print Spool Cache..."
    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\System32\spool\PRINTERS\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name "Spooler" -ErrorAction SilentlyContinue
}

# ------------------------ Run All ------------------------

# RAM & VRAM Performance Optimization Functions

function Set-PerformanceMode {
    Write-Host "Setting system to best performance (visual effects)..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2
    Set-ItemProperty -Path "HKCU:\Control Panel\Performance\Settings" -Name "VisualFXSetting" -Value 2
}

function Disable-Superfetch {
    Write-Host "Disabling Superfetch (SysMain) service..."
    Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SysMain" -StartupType Disabled
}

function Disable-WindowsSearch {
    Write-Host "Disabling Windows Search Indexing..."
    Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WSearch" -StartupType Disabled
}

function Disable-Hibernation {
    Write-Host "Disabling Hibernation..."
    powercfg -h off
}

function Set-GPUPreferenceHighPerformance {
    Write-Host "Setting GPU preference to High Performance for common apps..."

    $gpuKey = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"
    if (-not (Test-Path $gpuKey)) {
        New-Item -Path $gpuKey -Force | Out-Null
    }

    $apps = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Blender Foundation\Blender\blender.exe",
        "$env:ProgramFiles\Adobe\Adobe Photoshop\Photoshop.exe"
    )

    foreach ($app in $apps) {
        if (Test-Path $app) {
            $escapedPath = $app.Replace('\', '\\')
            Set-ItemProperty -Path $gpuKey -Name $escapedPath -Value "GpuPreference=2;"
            Write-Host "Set High Performance GPU for: $app"
        }
    }
}

function Set-HighPerformancePowerPlan {
    Write-Host "Enabling High Performance Power Plan..."
    powercfg -setactive SCHEME_MIN
}

function Flush-WorkingSets {
    Write-Host "Flushing Working Sets..."
    $processes = Get-Process | Where-Object { $_.Id -ne $PID }

    foreach ($proc in $processes) {
        try {
            [System.Diagnostics.Process]::GetProcessById($proc.Id).MinWorkingSet = 0
            [System.Diagnostics.Process]::GetProcessById($proc.Id).MaxWorkingSet = 0
        } catch {
            # Silently continue for protected/system processes
        }
    }
}

function Clear-StandbyRAM {
    Write-Host "Clearing Standby RAM..."
    $ramTool = "$env:TEMP\rammap.exe"
    $ramArgs = "-E"

    if (-Not (Test-Path $ramTool)) {
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/RAMMap.zip" -OutFile "$env:TEMP\RAMMap.zip"
        Expand-Archive "$env:TEMP\RAMMap.zip" -DestinationPath "$env:TEMP" -Force
    }

    Start-Process -FilePath $ramTool -ArgumentList $ramArgs -Wait
}

function Kill-GPUIntensiveApps {
    Write-Host "Terminating background GPU-heavy apps (optional list)..."
    $targets = "Photoshop", "Blender", "AfterFX", "chrome", "vlc"

    Get-Process | Where-Object { $targets -contains $_.Name } | ForEach-Object {
        try {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped: $($_.Name)"
        } catch {}
    }
}

function Show-GPUUsage {
    Write-Host "Fetching GPU Usage (NVIDIA only)..."
    & "$env:ProgramFiles\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
}

    Clear-TempFiles
    Remove-ShadowCopies
    Clear-Prefetch
    Remove-OldUpdates
    Remove-OldLogs
    Remove-MemoryDumps
    Run-DiskCleanup
    Clear-RecycleBin
    Clear-BrowsingCache
    Clear-WindowsDefenderCache
    Clean-Registry
    Remove-OldInstallerFiles
    Remove-OldBackupFiles
    Remove-OldEventLogs
    Clear-SuperFetch
    Clear-ErrorReports
    Clear-OldDrivers
    Clear-ClipboardHistory
    Clear-FontCache
    Clear-WindowsStoreCache
    Clear-DeliveryOptimization
    Clear-ThumbnailsCache
    Clear-ETLLogs
    Clear-DNSCache
    Clear-PrintSpool
    Set-PerformanceMode
    Disable-Superfetch
    Disable-WindowsSearch
    Disable-Hibernation
    Set-GPUPreferenceHighPerformance
    Set-HighPerformancePowerPlan
    Flush-WorkingSets
    Clear-StandbyRAM
    Kill-GPUIntensiveApps

# Call this function along with your main cleanup process:
Optimize-SystemPerformance


Write-Host "System Cleanup Complete!" -ForegroundColor Green
