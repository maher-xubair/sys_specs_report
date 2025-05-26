
# Require at least PowerShell 5.1 for CIM cmdlets
if ($PSVersionTable.PSVersion -lt [Version]"5.1") {
    Write-Warning "PowerShell 5.1+ is required. Attempting to launch PowerShell Core..."
    if (Get-Command pwsh -ErrorAction SilentlyContinue) {
        & pwsh -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
        exit
    } else {
        Write-Error "PowerShell Core (pwsh) not found. Please install it from https://aka.ms/pscore6"
        exit 1
    }
}


# Check for required modules
$requiredModules = @(
    @{Name="CimCmdlets"; Optional=$false},
    @{Name="NetAdapter"; Optional=$true},
    @{Name="BitLocker"; Optional=$true}
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module.Name)) {
        if (-not $module.Optional) {
            Write-Warning "Required module $($module.Name) is not available. Some features will be limited."
            # Add fallback logic for each module
        }
    }
}

# Check for admin rights early in the script
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Some information requires administrator privileges and will be limited."
    # Add logic to skip admin-only sections
}

# Verify write permissions before generating report
function Test-WriteAccess {
    param($Path)
    try {
        [IO.File]::OpenWrite($Path).Close()
        return $true
    } catch {
        return $false
    }
}

# Alternative save locations if default fails
$saveLocations = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:TEMP"
)

# Bypass Execution Policy
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage' -or
    (Get-ExecutionPolicy) -match 'Restricted|AllSigned') {
    Write-Verbose "Relaunching under Bypass execution policy..."
    & powershell -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @Args
    exit
}


function Get-RegistryInstallDate {
    $ts = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallDate -ErrorAction SilentlyContinue
    if ($ts) {
        return ([DateTimeOffset]::FromUnixTimeSeconds($ts)).LocalDateTime
    }
    return 'N/A'
}

function Safe-ConvertWmiDate {
    param([string]$d)
    if ([string]::IsNullOrEmpty($d)) { return 'N/A' }
    try { return [Management.ManagementDateTimeConverter]::ToDateTime($d) }
    catch { return 'Invalid Date' }
}

function Get-VirtStatus {
    $line = systeminfo | Select-String 'Virtualization.*:' -ErrorAction SilentlyContinue
    if ($line -and $line.Line -match ':\s*(Enabled)') { return $Matches[1] }
    else { return 'Disabled' }
}

function Map-SmbiosType {
    param($code)
    switch ($code) {
        0 {'Unknown'}
        20 {'DDR'}
        21 {'DDR2'}
        22 {'DDR2 FB-DIMM'}
        24 {'DDR3'}
        26 {'DDR4'}
        27 {'DDR5'}
        28 {'DDR5'}
        34 {'DDR5'}
        default { "Type $code" }
    }
}

function Get-TouchSupport {
    $touch = (Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match "HID-compliant touch" }).FriendlyName
    if ($touch) { return "Supported" } else { return "Not supported" }
}

# Generate unique filename
$count = 1
$dateStamp = Get-Date -Format "yyyy-MM-dd"
$timeStamp = Get-Date -Format "HH-mm-ss"
$reportFile = "system-specs-report-$count-$dateStamp.html"

while (Test-Path $reportFile) {
    $count++
    $reportFile = "system-specs-report-$count-$dateStamp.html"
}

Write-Host "Starting system information gathering..." -ForegroundColor Cyan

# Create HTML report
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Specification Report</title>
<link rel="shortcut icon" href="https://img.icons8.com/fluency/48/imac-settings.png" type="image/x-icon">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 15px; 
            color: #333;
            background-color: #f9f9f9;
            font-size: 0.9em; /* Slightly smaller base font */
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 15px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            border-radius: 5px;
        }
        h1 { 
            color: #2c3e50; 
            text-align: center;
            margin-bottom: 5px;
            font-size: 1.6em; /* Slightly smaller heading */
        }
        .subtitle {
            text-align: center;
            color: #7f8c8d;
            margin-bottom: 20px;
            font-size: 0.9em;
        }
        h2 { 
            color: #3498db; 
            margin-top: 25px; 
            border-bottom: 2px solid #3498db; 
            padding-bottom: 5px;
            font-size: 1.2em; /* Slightly smaller heading */
        }
        h3 {
            color: #16a085;
            margin-top: 15px;
            font-size: 1.0em; /* Slightly smaller heading */
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 15px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            font-size: 0.85em; /* Slightly smaller table font */
        }
        th { 
            background-color: #3498db; 
            color: white;
            text-align: left; 
            padding: 10px;
            font-weight: normal;
        }
        td { 
            padding: 8px; 
            border-bottom: 1px solid #ecf0f1;
            vertical-align: top;
            word-break: break-word;
        }
        tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        tr:hover {
            background-color: #f1f8fe;
        }
        .section { 
            margin-bottom: 30px;
        }
        .spec-value {
            font-weight: bold;
            color: #2c3e50;
        }
        .warning {
            color: #e74c3c;
            font-weight: bold;
        }
        .good {
            color: #27ae60;
            font-weight: bold;
        }
        .info {
            color: #3498db;
            font-weight: bold;
        }
        .property-name {
            width: 30%;
        }
        .system-overview {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 15px;
            background: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
        }
        .overview-item {
            flex: 1;
            min-width: 200px;
            margin: 5px;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #7f8c8d;
            font-size: 0.8em;
        }
        @media (max-width: 600px) {
            body {
                padding: 5px;
                font-size: 0.8em; /* Further reduce font size for mobile */
            }
            .container {
                padding: 10px;
            }
            h1 {
                font-size: 1.4em;
            }
            h2 {
                font-size: 1.1em;
            }
            h3 {
                font-size: 0.9em;
            }
            table {
                font-size: 0.75em; /* Further reduce table font size for mobile */
            }
            th, td {
                padding: 6px;
            }
            .overview-item {
                min-width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>System Specification Report</h1>
        <div class="subtitle">Generated on $(Get-Date -Format "yyyy-MM-dd hh:mm:ss tt")</div>
"@

Write-Host "Getting system overview..." -ForegroundColor Green
# System Information
$computerSystem = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$computerName = $env:COMPUTERNAME
$userName = $env:USERNAME
$lastBootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = New-TimeSpan -Start $lastBootTime -End (Get-Date)
$runtime = "$($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"

# Windows Information
$win32_OS = Get-CimInstance Win32_OperatingSystem
$winVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
$displayVersion = $winVer.DisplayVersion
$releaseId = $winVer.ReleaseId
$installDate = Get-RegistryInstallDate

# Device and Product ID
$deviceId = (Get-CimInstance Win32_ComputerSystemProduct).UUID
$productId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductId
if (-not $deviceId) { $deviceId = "N/A" }
if (-not $productId) { $productId = "N/A" }

# Pen and Touch Information
$touchSupport = Get-TouchSupport

# Virtualization Status
$virtStatus = Get-VirtStatus

# System Model
$systemModel = $($computerSystem.Model)

# Windows Activation Status
$windowsStatus = try {
    $lic = Get-CimInstance SoftwareLicensingProduct | Where-Object { $_.PartialProductKey -and $_.LicenseStatus -eq 1 }
    if ($lic -ne $null) { "Activated" } else { "Not Activated" }
} catch {
    "N/A"
}

# Chassis Type
$chassisTypes = try {
    $ce = Get-CimInstance Win32_SystemEnclosure
    if ($ce.ChassisTypes) { ($ce.ChassisTypes | ForEach-Object {
        switch ($_) {
            1 {"Other"}
            2 {"Unknown"}
            3 {"Desktop"}
            4 {"Low Profile Desktop"}
            5 {"Mini Tower"}
            6 {"Tower"}
            7 {"Portable"}
            8 {"Laptop"}
            9 {"Notebook"}
            10 {"Hand Held"}
            11 {"Docking Station"}
            12 {"All-in-One"}
            13 {"Sub Laptop"}
            14 {"Space-saving"}
            15 {"Lunch Box"}
            16 {"Main Server Chassis"}
            17 {"Expansion Chassis"}
            18 {"Sub Chassis"}
            19 {"Bus Expansion Chassis"}
            20 {"Peripheral Chassis"}
            21 {"RAID Chassis"}
            22 {"Rack Mount Chassis"}
            23 {"Sealed-case PC"}
            24 {"Tablet"}
            25 {"Convertible Laptop"}
            26 {"Detachable Laptop"}
            27 {"IoT Gateway"}
            28 {"Embedded PC"}
            29 {"Mini PC"}
            30 {"Stick PC"}
            default {"Type $_"}
        }
    }) -join ', ' } else { "N/A" }
} catch {
    "N/A"
}

# Language and Time Zone
$languageTimezone = try {
    $language = (Get-WinSystemLocale).Name
    $timezone = (Get-TimeZone).DisplayName
    "$language / $timezone"
} catch {
    "N/A"
}

$html += @"
        <div class="system-overview">
            <div class="overview-item">
                <h3>System Overview</h3>
                <p><span class="spec-value">$($computerSystem.Manufacturer) $systemModel</span></p>
                <p>Device Name: <span class="spec-value">$computerName</span></p>
                <p>User: <span class="spec-value">$userName</span></p>
                <p>System Type: <span class="spec-value">$($os.OSArchitecture)</span></p>
                <p>Uptime: <span class="spec-value">$runtime</span></p>
                <p>Language/TimeZone : <span class="spec-value">$languageTimezone</span></p>
            </div>
            <div class="overview-item">
                <h3>Windows Information</h3>
                <p>Edition: <span class="spec-value">$($winVer.EditionID)</span></p>
                <p>Version: <span class="spec-value">$displayVersion (OS Build $($winVer.CurrentBuildNumber).$($winVer.UBR))</span></p>
                <p>Installed on: <span class="spec-value">$installDate</span></p>
                <p>Experience: <span class="spec-value">Windows Feature Experience Pack $($winVer.ExperiencePackVersion)</span></p>
                <p>Pen and Touch: <span class="spec-value">$touchSupport</span></p>
                <p>Windows Status : <span class="spec-value">$windowsStatus</span></p>
            </div>
            <div class="overview-item">
                <h3>Device Information</h3>
                <p>Device ID: <span class="spec-value">$deviceId</span></p>
                <p>Product ID: <span class="spec-value">$productId</span></p>
                <p>System Manufacturer: <span class="spec-value">$($computerSystem.Manufacturer)</span></p>
                <p>System Model: <span class="spec-value">$systemModel</span></p>
                <p>Virtualization: <span class="spec-value">$virtStatus</span></p>
                <p>Chassis Types : <span class="spec-value">$chassisTypes</span></p>
            </div>
        </div>
"@

Write-Host "Getting CPU information..." -ForegroundColor Green
# CPU Information
$cpu = Get-CimInstance Win32_Processor
$cpuCores = $cpu.NumberOfCores
$cpuThreads = $cpu.NumberOfLogicalProcessors
$cpuArch = switch ($cpu.AddressWidth) {
    32 { "x86" }
    64 { "x64" }
    default { "Unknown" }
}

$html += @"
        <div class="section">
            <h2>CPU Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Name</td><td><span class="spec-value">$($cpu.Name)</span></td></tr>
                <tr><td>Manufacturer</td><td>$($cpu.Manufacturer)</td></tr>
                <tr><td>Architecture</td><td>$cpuArch</td></tr>
                <tr><td>Cores</td><td>$cpuCores</td></tr>
                <tr><td>Threads</td><td>$cpuThreads</td></tr>
                <tr><td>Current Clock Speed</td><td>$($cpu.CurrentClockSpeed) MHz</td></tr>
                <tr><td>Max Clock Speed</td><td>$($cpu.MaxClockSpeed) MHz</td></tr>
                <tr><td>L2 Cache</td><td>$([math]::Round($cpu.L2CacheSize / 1KB, 2)) MB</td></tr>
                <tr><td>L3 Cache</td><td>$([math]::Round($cpu.L3CacheSize / 1KB, 2)) MB</td></tr>
                <tr><td>Socket Designation</td><td>$($cpu.SocketDesignation)</td></tr>
                <tr><td>Virtualization Enabled</td><td>$($cpu.VirtualizationFirmwareEnabled)</td></tr>
                <tr><td>Current Voltage</td><td>$($cpu.CurrentVoltage / 10)V</td></tr>
            </table>
        </div>
"@

Write-Host "Getting memory information..." -ForegroundColor Green
# Memory Information with DDR detection
$memory = Get-CimInstance Win32_PhysicalMemory
$totalMemoryGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
$totalMemoryMB = [math]::Round($computerSystem.TotalPhysicalMemory / 1MB, 2)

$html += @"
        <div class="section">
            <h2>Memory Information</h2>
            <p><strong>Total RAM:</strong> <span class="spec-value">$totalMemoryGB GB ($totalMemoryMB MB)</span></p>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
"@

foreach ($mem in $memory) {
    $capacityGB = [math]::Round($mem.Capacity / 1GB, 2)
    $capacityMB = [math]::Round($mem.Capacity / 1MB, 2)
    $ddrGen = Map-SmbiosType $mem.SmbiosMemoryType
    
    # Determine RAM manufacturer from PartNumber if Manufacturer is blank
    $manufacturer = $mem.Manufacturer
    if ([string]::IsNullOrWhiteSpace($manufacturer)) {
        if ($mem.PartNumber -match "Samsung") { $manufacturer = "Samsung" }
        elseif ($mem.PartNumber -match "Micron") { $manufacturer = "Micron" }
        elseif ($mem.PartNumber -match "Hynix") { $manufacturer = "SK Hynix" }
        elseif ($mem.PartNumber -match "Kingston") { $manufacturer = "Kingston" }
        elseif ($mem.PartNumber -match "Corsair") { $manufacturer = "Corsair" }
        else { $manufacturer = "Unknown" }
    }
    
    $html += @"
                <tr><td colspan="2" style="background-color: #e3f2fd;"><strong>Module in $($mem.DeviceLocator)</strong></td></tr>
                <tr><td>Manufacturer</td><td>$manufacturer</td></tr>
                <tr><td>Part Number</td><td>$(if($mem.PartNumber) {$mem.PartNumber} else {'N/A'})</td></tr>
                <tr><td>Serial Number</td><td>$(if($mem.SerialNumber) {$mem.SerialNumber} else {'N/A'})</td></tr>
                <tr><td>Capacity</td><td>$capacityGB GB ($capacityMB MB)</td></tr>
                <tr><td>Type</td><td>$ddrGen</td></tr>
                <tr><td>Speed</td><td>$($mem.Speed) MHz</td></tr>
                <tr><td>Form Factor</td><td>$($mem.FormFactor)</td></tr>
                <tr><td>Bank Label</td><td>$(if($mem.BankLabel) {$mem.BankLabel} else {'N/A'})</td></tr>
"@
}

$html += @"
            </table>
        </div>
"@

Write-Host "Getting storage information..." -ForegroundColor Green
# Disk Information using PhysicalDisk class
$disks = Get-PhysicalDisk
$logicalDisks = Get-Volume | Where-Object DriveLetter

$html += @"
        <div class="section">
            <h2>Storage Information</h2>
            <h3>Physical Disks</h3>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
"@

foreach ($disk in $disks) {
    $sizeGB = [math]::Round($disk.Size / 1GB, 2)
    $sizeMB = [math]::Round($disk.Size / 1MB, 2)
    
    # Disk type detection
    $busType = switch ($disk.BusType) {
        0 { "Unknown" }
        1 { "SCSI" }
        2 { "ATAPI" }
        3 { "ATA" }
        4 { "IEEE 1394" }
        5 { "SSA" }
        6 { "Fibre Channel" }
        7 { "USB" }
        8 { "RAID" }
        9 { "iSCSI" }
        10 { "SAS" }
        11 { "SATA" }
        12 { "SD" }
        13 { "MMC" }
        14 { "Virtual" }
        15 { "File Backed Virtual" }
        16 { "Storage Spaces" }
        17 { "NVMe" }
        default { "$($disk.BusType)" }
    }
    
    $mediaType = switch ($disk.MediaType) {
        0 { "Unspecified" }
        3 { "HDD" }
        4 { "SSD" }
        5 { "SCM" }
        default { "$($disk.MediaType)" }
    }
    
    # Attempt to get manufacturer from Win32_DiskDrive if PhysicalDisk.Manufacturer is N/A
    $diskManufacturer = $disk.Manufacturer
    if ([string]::IsNullOrWhiteSpace($diskManufacturer) -or $diskManufacturer -eq "N/A") {
        $wmiDisk = Get-CimInstance Win32_DiskDrive | Where-Object { $_.SerialNumber -eq $disk.SerialNumber }
        if ($wmiDisk -and -not [string]::IsNullOrWhiteSpace($wmiDisk.Manufacturer)) {
            $diskManufacturer = $wmiDisk.Manufacturer
        } else {
            $diskManufacturer = 'N/A'
        }
    }

    $html += @"
                <tr><td colspan="2" style="background-color: #e3f2fd;"><strong>$($disk.FriendlyName)</strong></td></tr>
                <tr><td>Manufacturer</td><td>$diskManufacturer</td></tr>
                <tr><td>Model</td><td>$(if($disk.Model) {$disk.Model} else {'N/A'})</td></tr>
                <tr><td>Size</td><td>$sizeGB GB ($sizeMB MB)</td></tr>
                <tr><td>Type</td><td>$mediaType</td></tr>
                <tr><td>Interface</td><td>$busType</td></tr>
                <tr><td>Serial Number</td><td>$(if($disk.SerialNumber) {$disk.SerialNumber} else {'N/A'})</td></tr>
                <tr><td>Health Status</td><td>$(if($disk.HealthStatus) {$disk.HealthStatus} else {'N/A'})</td></tr>
                <tr><td>Operational Status</td><td>$(if($disk.OperationalStatus) {$disk.OperationalStatus} else {'N/A'})</td></tr>
"@
}

$html += @"
            </table>
            
            <h3>Logical Drives</h3>
            <table>
                <tr><th>Drive</th><th>File System</th><th>BitLocker Status</th><th>Size</th><th>Free Space</th><th>Free %</th><th>Volume Name</th></tr>
"@

foreach ($disk in $logicalDisks) {
    $sizeGB = [math]::Round($disk.Size / 1GB, 2)
    $freeGB = [math]::Round($disk.SizeRemaining / 1GB, 2)
    $freePercent = if ($disk.Size -gt 0) { [math]::Round(($disk.SizeRemaining / $disk.Size) * 100, 2) } else { 0 }
    $freeClass = if ($freePercent -lt 10) { "warning" } elseif ($freePercent -lt 20) { "info" } else { "good" }
    
    $volumeName = if ($disk.FileSystemLabel) { $disk.FileSystemLabel } else { "N/A" }
    
    $bitlockerStatus = try {
        $bitlockerVolume = Get-BitLockerVolume -MountPoint "$($disk.DriveLetter):" -ErrorAction SilentlyContinue
        if ($bitlockerVolume) { $bitlockerVolume.ProtectionStatus } else { "N/A" }
    } catch {
        "N/A"
    }

    $html += @"
                <tr>
                    <td>$($disk.DriveLetter):</td>
                    <td>$($disk.FileSystem)</td>
                    <td>$bitlockerStatus</td>
                    <td>$sizeGB GB</td>
                    <td>$freeGB GB</td>
                    <td><span class="$freeClass">$freePercent%</span></td>
                    <td>$volumeName</td>
                </tr>
"@
}

$html += @"
            </table>
        </div>
"@

Write-Host "Getting graphics information..." -ForegroundColor Green
# GPU Information
$gpus = Get-CimInstance Win32_VideoController
$displaySettings = Get-CimInstance Win32_DisplayConfiguration

$html += @"
        <div class="section">
            <h2>Graphics Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
"@

foreach ($gpu in $gpus) {
    $vramGB = [math]::Round($gpu.AdapterRAM / 1GB, 2)
    $vramMB = [math]::Round($gpu.AdapterRAM / 1MB, 2)
    $driverDate = if ($gpu.DriverDate -match '^\d{8}') { Safe-ConvertWmiDate $gpu.DriverDate } else { 'N/A' }
    
    $html += @"
                <tr><td colspan="2" style="background-color: #e3f2fd;"><strong>$($gpu.Name)</strong></td></tr>
                <tr><td>Adapter RAM</td><td>$vramGB GB ($vramMB MB)</td></tr>
                <tr><td>Driver Version</td><td>$(if($gpu.DriverVersion) {$gpu.DriverVersion} else {'N/A'})</td></tr>
                <tr><td>Driver Date</td><td>$driverDate</td></tr>
                <tr><td>Video Processor</td><td>$(if($gpu.VideoProcessor) {$gpu.VideoProcessor} else {'N/A'})</td></tr>
                <tr><td>Current Resolution</td><td>$($gpu.CurrentHorizontalResolution)x$($gpu.CurrentVerticalResolution) @ $($gpu.CurrentRefreshRate)Hz</td></tr>
                <tr><td>Color Depth</td><td>$($gpu.CurrentBitsPerPixel) bits</td></tr>
"@
}

Write-Host "Getting Display information..." -ForegroundColor Green
# Display Information
$html += @"
            </table>
            <h3>Display Information</h3>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
"@

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Screen]::AllScreens | ForEach-Object {
    $bounds = $_.Bounds
    $monitorName = $_.DeviceName
    $resolution = "$($bounds.Width)x$($bounds.Height)"

    $refreshRate = 'N/A'
    try {
        $disp = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction Stop | Select-Object -First 1
        if ($disp) {
            $refreshRate = "$($disp.MaxVerticalImageSize) Hz (approx.)"
        }
    } catch {}

    $manufacturer = 'N/A'
    $model = 'N/A'
    try {
        $id = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction Stop | Select-Object -First 1
        if ($id) {
            $manufacturer = -join ($id.ManufacturerName | ForEach-Object {[char]$_})
            $model = -join ($id.ProductCodeID | ForEach-Object {[char]$_})
        }
    } catch {}

    $html += @"
                <tr><td colspan="2" style="background-color: #e3f2fd;"><strong>$monitorName</strong></td></tr>
                <tr><td>Monitor</td><td>$monitorName</td></tr>
                <tr><td>Resolution</td><td>$resolution</td></tr>
                <tr><td>Refresh Rate</td><td>$refreshRate</td></tr>
                <tr><td>Manufacturer</td><td>$manufacturer</td></tr>
                <tr><td>Model</td><td>$model</td></tr>
"@
}
$html += @"
            </table>
        </div>
"@


Write-Host "Getting network information..." -ForegroundColor Green
# Network Information with connection status
$nics = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true }
$networkConfigs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }

# Fetch Wi-Fi info once
$wifiVersion = "N/A"
$supportedPhy = "N/A"
try {
    $wifiData = netsh wlan show drivers
    $phyMatch = $wifiData | Select-String "Radio types supported"
    if ($phyMatch) {
        $supportedPhy = ($phyMatch -split ":", 2)[1].Trim()
        if ($supportedPhy -match "ax")       { $wifiVersion = "Wi-Fi 6 (802.11ax)" }
        elseif ($supportedPhy -match "ac")   { $wifiVersion = "Wi-Fi 5 (802.11ac)" }
        elseif ($supportedPhy -match "n")    { $wifiVersion = "Wi-Fi 4 (802.11n)" }
        else                                 { $wifiVersion = "Legacy/Unknown" }
    }
} catch {}

$html += @"
        <div class="section">
            <h2>Network Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
"@

if($nics){


foreach ($nic in $nics) {
    $config = $networkConfigs | Where-Object { $_.Index -eq $nic.Index }
    $speed = if ($nic.Speed) { "$([math]::Round($nic.Speed / 1MB, 2)) Mbps" } else { "Unknown" }
    $connectionStatus = if ($nic.NetConnectionStatus -eq 2) { "Connected" } else { "Disconnected" }
    $connectionType = if ($nic.Name -like "*Wi-Fi*" -or $nic.Name -like "*Wireless*") { "Wi-Fi" } else { "Ethernet" }
    
    $ipAddresses = if ($config) { $config.IPAddress -join ", " } else { "N/A" }
    $dnsServers = if ($config -and $config.DNSServerSearchOrder) { $config.DNSServerSearchOrder -join ", " } else { "N/A" }

    $html += @"
                <tr><td colspan="2" style="background-color: #e3f2fd;"><strong>$($nic.Name)</strong></td></tr>
                <tr><td>Connection Type</td><td>$connectionType</td></tr>
                <tr><td>Status</td><td>$connectionStatus</td></tr>
                <tr><td>MAC Address</td><td>$(if($nic.MACAddress) {$nic.MACAddress} else {'N/A'})</td></tr>
                <tr><td>Speed</td><td>$speed</td></tr>
                <tr><td>IP Address(es)</td><td>$ipAddresses</td></tr>
                <tr><td>DNS Servers</td><td>$dnsServers</td></tr>
                <tr><td>Supported PHY</td><td>$supportedPhy</td></tr>
                <tr><td>Wi-Fi Version</td><td>$wifiVersion</td></tr>
"@
}
} else {
        $html += @"
                <tr><td colspan="2">No Wifi adapters found or enabled.</td></tr>
"@
}


Write-Host "Getting Bluetooth information..." -ForegroundColor Green
# Bluetooth Information
$html += @"
            </table>
            <h3>Bluetooth Information</h3>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
"@

# LMP to Bluetooth version mapping function
function Get-BluetoothVersionFromLMP($lmp) {
    switch ($lmp) {
        0 { return "1.0b" }
        1 { return "1.1" }
        2 { return "1.2" }
        3 { return "2.0" }
        4 { return "2.1" }
        5 { return "3.0" }
        6 { return "4.0" }
        7 { return "4.1" }
        8 { return "4.2" }
        9 { return "5.0" }
        10 { return "5.1" }
        11 { return "5.2" }
        12 { return "5.3" }
        13 { return "5.4" }
        14 { return "6.0" }
        default { return "Unknown / Unable to read LMP" }
    }
}

# Helper: try get LMP version from registry keys
function Get-LMPVersionFromRegistry {
    $paths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices",
        "HKLM:\SYSTEM\CurrentControlSet\Services\BTHENUM\Parameters\Devices"
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            foreach ($deviceKey in Get-ChildItem $path -ErrorAction SilentlyContinue) {
                $lmp = (Get-ItemProperty -Path $deviceKey.PSPath -Name 'LMPVersion' -ErrorAction SilentlyContinue).LMPVersion
                if ($lmp -ne $null) {
                    return [int]$lmp
                }
            }
        }
    }
    return $null
}

# Get Bluetooth devices
$bluetoothDevices = Get-PnpDevice -Class Bluetooth -Status OK -ErrorAction SilentlyContinue
if ($bluetoothDevices) {
    foreach ($bt in $bluetoothDevices) {
        $btName = if ($bt.FriendlyName) { $bt.FriendlyName } else { "N/A" }
        $btDriverVersion = "N/A"
        $btDriverDate = "N/A"
        $btVersion = "Unknown / Unable to read LMP"
        $btStatus = if ($bt.Status) { $bt.Status } else { "N/A" }

        try {
            $drv = Get-CimInstance Win32_PnPSignedDriver | Where-Object DeviceName -EQ $bt.FriendlyName -ErrorAction Stop
            if ($drv) {
                $btDriverVersion = if ($drv.DriverVersion) { $drv.DriverVersion } else { "N/A" }
                $btDriverDate = if ($drv.DriverDate) { $drv.DriverDate.ToString('yyyy-MM-dd') } else { "N/A" }
            }
        } catch {}

        # Try get LMP from device property first
        $lmpVersion = $null
        try {
            $lmpVersion = Get-PnpDeviceProperty -InstanceId $bt.InstanceId -KeyName 'DEVPKEY_Device_Bluetooth_LMPVersion' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Data
            if ($lmpVersion -ne $null) {
                $lmpVersion = [int]$lmpVersion
            }
        } catch {}

        # Fallback: try registry if LMP from property is null
        if ($lmpVersion -eq $null) {
            $lmpVersion = Get-LMPVersionFromRegistry
        }

        # Map LMP to Bluetooth version
        if ($lmpVersion -ne $null) {
            $btVersion = Get-BluetoothVersionFromLMP $lmpVersion
        }

        $html += @"
                <tr><td colspan='2' style='background-color: #e3f2fd;'><strong>$btName</strong></td></tr>
                <tr><td>Driver Version</td><td>$btDriverVersion</td></tr>
                <tr><td>Driver Date</td><td>$btDriverDate</td></tr>
                <tr><td>Bluetooth Version</td><td>$btVersion</td></tr>
                <tr><td>Status</td><td>$btStatus</td></tr>
"@
    }
} else {
    $html += @"
                <tr><td colspan='2'>No Bluetooth adapters found or enabled.</td></tr>
"@
}

$html += @"
            </table>
        </div>
"@


Write-Host "Getting battery information..." -ForegroundColor Green
# Battery Information
$batt = Get-CimInstance Win32_Battery
if ($batt) {
    $html += @"
        <div class="section">
            <h2>Battery Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
"@

    foreach ($b in $batt) {
        $chargeRemaining = if ($b.EstimatedChargeRemaining -ne $null) { "$($b.EstimatedChargeRemaining)%" } else { 'Unknown' }
        
        $html += @"
                <tr><td colspan="2" style="background-color: #e3f2fd;"><strong>$($b.Name)</strong></td></tr>
                <tr><td>Manufacturer</td><td>$(if($b.Manufacturer) {$b.Manufacturer} else {'N/A'})</td></tr>
                <tr><td>Chemistry</td><td>$(if($b.Chemistry) {$b.Chemistry} else {'N/A'})</td></tr>
                <tr><td>Design Capacity</td><td>$(if($b.DesignCapacity) {"$($b.DesignCapacity)mWh"} else {'N/A'})</td></tr>
                <tr><td>Full Charge Capacity</td><td>$(if($b.FullChargedCapacity) {"$($b.FullChargedCapacity)mWh"} else {'N/A'})</td></tr>
                <tr><td>Charge Remaining</td><td>$chargeRemaining</td></tr>
                <tr><td>Status</td><td>$(switch ($b.BatteryStatus) {
                    1 { "Discharging" }
                    2 { "On AC Power" }
                    3 { "Fully Charged" }
                    4 { "Low" }
                    5 { "Critical" }
                    6 { "Charging" }
                    7 { "Charging High" }
                    8 { "Charging Low" }
                    9 { "Charging Critical" }
                    10 { "Undefined" }
                    11 { "Partially Charged" }
                    default { "Unknown ($($b.BatteryStatus))" }
                })</td></tr>
                <tr><td>Runtime Estimate</td><td>$(if($b.EstimatedRunTime) {"$($b.EstimatedRunTime) min"} else {'N/A'})</td></tr>
                <tr><td>Time On Battery</td><td>$(if($b.TimeOnBattery) {"$($b.TimeOnBattery) min"} else {'N/A'})</td></tr>
"@
    }

    $html += @"
            </table>
        </div>
"@
} else {
    $html += @"
        <div class="section">
            <h2>Battery Information</h2>
            <p>No battery data available</p>
        </div>
"@
}

Write-Host "Getting motherboard and BIOS information..." -ForegroundColor Green
# Motherboard and BIOS Information
$mb = Get-CimInstance Win32_BaseBoard
# Use Get-WmiObject specifically for BIOS ReleaseDate as per user's working snippet
$biosWmi = Get-WmiObject Win32_BIOS
$biosCim = Get-CimInstance Win32_BIOS # Keep this for other BIOS properties

$biosDate = 'N/A'
if ($biosWmi -and $biosWmi.ReleaseDate) {
    try {
        $biosDate = [Management.ManagementDateTimeConverter]::ToDateTime($biosWmi.ReleaseDate)
    } catch {
        $biosDate = 'Invalid Date (Conversion Error)'
    }
}

$html += @"
        <div class="section">
            <h2>Motherboard & BIOS</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td colspan="2" style="background-color: #e3f2fd;"><strong>Motherboard</strong></td></tr>
                <tr><td>Manufacturer</td><td>$(if($mb.Manufacturer) {$mb.Manufacturer} else {'N/A'})</td></tr>
                <tr><td>Product</td><td>$(if($mb.Product) {$mb.Product} else {'N/A'})</td></tr>
                <tr><td>Serial Number</td><td>$(if($mb.SerialNumber) {$mb.SerialNumber} else {'N/A'})</td></tr>
                <tr><td>Version</td><td>$(if($mb.Version) {$mb.Version} else {'N/A'})</td></tr>
                <tr><td colspan="2" style="background-color: #e3f2fd;"><strong>BIOS</strong></td></tr>
                <tr><td>Manufacturer</td><td>$(if($biosCim.Manufacturer) {$biosCim.Manufacturer} else {'N/A'})</td></tr>
                <tr><td>Name</td><td>$(if($biosCim.Name) {$biosCim.Name} else {'N/A'})</td></tr>
                <tr><td>Version</td><td>$(if($biosCim.Version) {$biosCim.Version} else {'N/A'})</td></tr>
                <tr><td>Serial Number</td><td>$(if($biosCim.SerialNumber) {$biosCim.SerialNumber} else {'N/A'})</td></tr>
                <tr><td>Release Date</td><td>$biosDate</td></tr>
                <tr><td>SMBIOS Version</td><td>$(if($biosCim.SMBIOSMajorVersion) {"$($biosCim.SMBIOSMajorVersion).$($biosCim.SMBIOSMinorVersion)"} else {'N/A'})</td></tr>
            </table>
        </div>
"@

Write-Host "Getting Boot and TPM information..." -ForegroundColor Green
# New Secure Boot & TPM Section
$secureBootEnabled = try {
    $sb = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name UEFISecureBootEnabled -ErrorAction Stop
    if ($sb.UEFISecureBootEnabled -eq 1) { "Enabled" } else { "Disabled" }
} catch {
    "N/A"
}

$tpmPresent = "N/A"
$tpmVersion = "N/A"
try {
    $t = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop
    if ($t) {
        if ($t.IsEnabled_InitialValue) {
            $tpmPresent = "True"
            $tpmVersion = if ($t.SpecVersion) { $t.SpecVersion } else { "N/A" }
        } else {
            $tpmPresent = "False"
            $tpmVersion = "N/A"
        }
    } else {
        $tpmPresent = "False"
        $tpmVersion = "N/A"
    }
} catch {
    $tpmPresent = "N/A"
    $tpmVersion = "N/A"
}

# Get last boot time
try {
    $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $lastBootTime = if ($lastBoot) { $lastBoot.ToString() } else { "N/A" }
} catch {
    $lastBootTime = "N/A"
}

$html += @"
        <div class="section">
            <h2>Boot & TPM Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Secure Boot Status</td><td>$secureBootEnabled</td></tr>
                <tr><td>TPM Present</td><td>$tpmPresent</td></tr>
                <tr><td>TPM Version</td><td>$tpmVersion</td></tr>
                <tr><td>Last Boot Up</td><td>$lastBootTime</td></tr>
            </table>
        </div>
"@

# Finalize HTML
$html += @"
        <div class="footer">
    <p>Report generated by System Specs Reporter - $(Get-Date -Format "yyyy")</p>
    <p>Designed and developed by <a href="https://nexoracle.com" target="_blank" style="text-decoration: underline; color: inherit;">NexOracle</a></p>
</div>
    </div>
</body>
</html>
"@

Write-Host "Saving report to $reportFile..." -ForegroundColor Green
# Save the report
$html | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Report generation complete!" -ForegroundColor Green
# Open the report
Write-Host "Report generated: $reportFile" -ForegroundColor Green
$open = Read-Host "Would you like to open the report now? (Y/N)"
if ($open -eq "" -or $open -eq "Y" -or $open -eq "y") { # Default to Y on empty input
    Start-Process $reportFile
}