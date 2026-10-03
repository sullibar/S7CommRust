# Open an existing TIA V21 project and download it to the PLCSIM Advanced instance, which
# switches the simulator to that project. -InfoOnly just prints the project's CPU.
param([Parameter(Mandatory)][string]$ProjectPath, [switch]$InfoOnly)
$ErrorActionPreference = 'Stop'
$d = "C:\Program Files\Siemens\Automation\Portal V21\PublicAPI\V21\net48"
Get-ChildItem "$d\Siemens.Engineering*.dll" | ForEach-Object { [void][Reflection.Assembly]::LoadFrom($_.FullName) }

function Log($m) { "$(Get-Date -Format HH:mm:ss) $m" }
function Svc($obj, [type]$t) {
    [Siemens.Engineering.IEngineeringServiceProvider].GetMethod('GetService').MakeGenericMethod($t).Invoke($obj, $null)
}
function All-Items($items) { foreach ($i in $items) { $i; All-Items $i.DeviceItems } }

$tia = New-Object Siemens.Engineering.TiaPortal ([Siemens.Engineering.TiaPortalMode]::WithoutUserInterface)
Log 'TIA started'
try {
    $project = $tia.Projects.Open([IO.FileInfo]$ProjectPath)
    Log "opened $($project.Path)"
    $device = $project.Devices | Select-Object -First 1
    $items = @(All-Items $device.DeviceItems)
    $cpuItem = $items | Where-Object { Svc $_ ([Siemens.Engineering.HW.Features.SoftwareContainer]) } | Select-Object -First 1
    $order = try { $cpuItem.GetAttribute('OrderNumber') } catch { '?' }
    $fw = try { $cpuItem.GetAttribute('FirmwareVersion') } catch { '?' }
    Log "CPU item: $($cpuItem.Name) $order FW $fw"
    if ($InfoOnly) { $project.Close(); return }

    $dp = Svc $cpuItem ([Siemens.Engineering.Download.DownloadProvider])
    $mode = $dp.Configuration.Modes.Find('PN/IE')
    $pc = $mode.PcInterfaces | Where-Object Name -like '*PLCSIM*' | Select-Object -First 1
    $target = $pc.TargetInterfaces | Select-Object -First 1
    Log "download via '$($pc.Name)' -> '$($target.Name)'"

    $prefer = 'StopAll', 'ConsistentDownload', 'StartModule', 'Overwrite', 'DownloadAllBlocks', 'DeleteAll', 'AcceptAll', 'StopPlcAndReinitialize', 'Wait', 'ContinueDownloading', 'DownloadAllUserManagementDataResetToProject'
    $handler = {
        param($cfg)
        $t = $cfg.GetType().Name
        $p = $cfg.GetType().GetProperty('CurrentSelection')
        if ($p) {
            $names = [Enum]::GetNames($p.PropertyType)
            $pick = $prefer | Where-Object { $names -contains $_ } | Select-Object -First 1
            if ($pick) { $cfg.CurrentSelection = [Enum]::Parse($p.PropertyType, $pick) }
            Write-Host "    cfg $t : $($cfg.CurrentSelection)  (options: $($names -join ', '))"
        } elseif ($cfg.GetType().GetProperty('Checked')) {
            $cfg.Checked = $true
            Write-Host "    cfg $t : checked"
        } else {
            Write-Host "    cfg $t : $($cfg.Message)"
        }
    }
    $dp.Configuration.add_OnlineLegitimation([Siemens.Engineering.Online.OnlineConfigurationDelegate]{
        param($cfg)
        if ($cfg -is [Siemens.Engineering.Online.Configurations.TlsVerificationConfiguration]) {
            $cfg.CurrentSelection = [Siemens.Engineering.Online.Configurations.TlsVerificationConfigurationSelection]::Trusted
            Write-Host "    online: trusted TLS certificate of $($cfg.PlcName)"
        } else {
            Write-Host "    online: $($cfg.GetType().Name) (unhandled)"
        }
    })
    $pre = [Siemens.Engineering.Download.DownloadConfigurationDelegate]$handler
    $post = [Siemens.Engineering.Download.DownloadConfigurationDelegate]$handler
    $opts = [Siemens.Engineering.Download.DownloadOptions]'Hardware, Software'
    $dl = $dp.Download($target, $pre, $post, $opts)
    Log "download: $($dl.State) (errors $($dl.ErrorCount), warnings $($dl.WarningCount))"
    foreach ($m in $dl.Messages) { "  [$($m.State)] $($m.Message)"; foreach ($c in $m.Messages) { "    [$($c.State)] $($c.Message)" } }
    $project.Close()
} finally {
    $tia.Dispose()
}
