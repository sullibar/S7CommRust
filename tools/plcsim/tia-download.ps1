# Open an existing TIA V21 project and download it to the PLCSIM Advanced instance, which
# switches the simulator to that project. -InfoOnly just prints the project's CPU.
#   -ChangesOnly  download only the program's changes (no hardware config)
#   -NoStop       keep the CPU in RUN; TIA refuses (StopModules unhandled) if the change needs a stop
#   -Password     the full-access password, for a PLC the project protects (see tia-protect.ps1)
param(
    [Parameter(Mandatory)][string]$ProjectPath,
    [switch]$InfoOnly,
    [switch]$ChangesOnly,
    [switch]$NoStop,
    [string]$Password
)
$ErrorActionPreference = 'Stop'
$d = "C:\Program Files\Siemens\Automation\Portal V21\PublicAPI\V21\net48"
Get-ChildItem "$d\Siemens.Engineering*.dll" | ForEach-Object { [void][Reflection.Assembly]::LoadFrom($_.FullName) }

function Log($m) { "$(Get-Date -Format HH:mm:ss) $m" }
function Svc($obj, [type]$t) {
    [Siemens.Engineering.IEngineeringServiceProvider].GetMethod('GetService').MakeGenericMethod($t).Invoke($obj, $null)
}
function All-Items($items) { foreach ($i in $items) { $i; All-Items $i.DeviceItems } }
function Secure($s) { $ss = New-Object System.Security.SecureString; foreach ($c in $s.ToCharArray()) { $ss.AppendChar($c) }; $ss.MakeReadOnly(); $ss }

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

    $script:noStop = [bool]$NoStop
    $script:pw = $Password
    $handler = {
        param($cfg)
        $t = $cfg.GetType().Name
        $p = $cfg.GetType().GetProperty('CurrentSelection')
        if ($p) {
            $names = [Enum]::GetNames($p.PropertyType)
            $prefer = if ($script:noStop -and $t -in 'StopModules', 'ResetModule') {
                'NoAction'
            } elseif ($script:noStop) {
                'NoAction', 'ConsistentDownload', 'StartModule', 'Overwrite', 'DownloadAllBlocks', 'AcceptAll', 'Wait', 'ContinueDownloading'
            } else {
                'StopAll', 'ConsistentDownload', 'StartModule', 'Overwrite', 'DownloadAllBlocks', 'DeleteAll', 'AcceptAll', 'StopPlcAndReinitialize', 'Wait', 'ContinueDownloading', 'DownloadAllUserManagementDataResetToProject'
            }
            # TIA refuses a choice the change doesn't allow (e.g. NoAction when a stop is needed).
            foreach ($pick in @($prefer | Where-Object { $names -contains $_ })) {
                try { $cfg.CurrentSelection = [Enum]::Parse($p.PropertyType, $pick); break }
                catch { Write-Host "    cfg $t : refused $pick" }
            }
            Write-Host "    cfg $t : $($cfg.CurrentSelection)  (options: $($names -join ', '))"
        } elseif ($cfg.GetType().GetProperty('Checked')) {
            $cfg.Checked = $true
            Write-Host "    cfg $t : checked"
        } elseif ($cfg.GetType().GetMethod('SetPassword') -and $script:pw) {
            # ModuleWriteAccessPassword on a protected PLC.
            $cfg.SetPassword((Secure $script:pw))
            Write-Host "    cfg $t : password given"
        } else {
            Write-Host "    cfg $t : $($cfg.Message)"
        }
    }
    $dp.Configuration.add_OnlineLegitimation([Siemens.Engineering.Online.OnlineConfigurationDelegate]{
        param($cfg)
        if ($cfg -is [Siemens.Engineering.Online.Configurations.TlsVerificationConfiguration]) {
            $cfg.CurrentSelection = [Siemens.Engineering.Online.Configurations.TlsVerificationConfigurationSelection]::Trusted
            Write-Host "    online: trusted TLS certificate of $($cfg.PlcName)"
        } elseif ($cfg -is [Siemens.Engineering.Online.Configurations.OnlineAuthenticationConfiguration] -and $script:pw) {
            $cfg.OnlineCredentials.SetPassword((Secure $script:pw))
            Write-Host "    online: logged in with the full-access password"
        } elseif ($cfg -is [Siemens.Engineering.Online.Configurations.OnlinePasswordConfiguration] -and $script:pw) {
            $cfg.SetPassword((Secure $script:pw))
            Write-Host "    online: answered the password prompt"
        } else {
            Write-Host "    online: $($cfg.GetType().Name) (unhandled)"
        }
    })
    $pre = [Siemens.Engineering.Download.DownloadConfigurationDelegate]$handler
    $post = [Siemens.Engineering.Download.DownloadConfigurationDelegate]$handler
    $opts = if ($ChangesOnly) {
        [Siemens.Engineering.Download.DownloadOptions]'SoftwareOnlyChanges'
    } else {
        [Siemens.Engineering.Download.DownloadOptions]'Hardware, Software'
    }
    $dl = $dp.Download($target, $pre, $post, $opts)
    Log "download: $($dl.State) (errors $($dl.ErrorCount), warnings $($dl.WarningCount))"
    foreach ($m in $dl.Messages) { "  [$($m.State)] $($m.Message)"; foreach ($c in $m.Messages) { "    [$($c.State)] $($c.Message)" } }
    $project.Close()
} finally {
    $tia.Dispose()
}
