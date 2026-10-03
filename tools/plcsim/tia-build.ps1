# Create a TIA V21 test project (a CPU 1511 at 169.254.130.10 with full access, and the two data
# blocks every test project has), compile it and download it to PLCSIM Advanced. Replaces an
# existing project of the same name under $Root. See README.md.
param(
    [string]$Root = "$env:TEMP\s7plcsim",
    [string]$ProjectName = 'S7CommRustTest',
    # FW V2.9 speaks TLS; V2.8 the legacy, non-TLS scheme.
    [string]$Cpu = 'OrderNumber:6ES7 511-1AK02-0AB0/V2.9',
    [string]$Ip = '169.254.130.10',
    [string]$Mask = '255.255.0.0',
    [switch]$Introspect
)
$ErrorActionPreference = 'Stop'
$d = "C:\Program Files\Siemens\Automation\Portal V21\PublicAPI\V21\net48"
Get-ChildItem "$d\Siemens.Engineering*.dll" | ForEach-Object { [void][Reflection.Assembly]::LoadFrom($_.FullName) }

function Log($m) { "$(Get-Date -Format HH:mm:ss) $m" }
function Svc($obj, [type]$t) {
    [Siemens.Engineering.IEngineeringServiceProvider].GetMethod('GetService').MakeGenericMethod($t).Invoke($obj, $null)
}
function All-Items($items) { foreach ($i in $items) { $i; All-Items $i.DeviceItems } }
function Show-Attrs($obj, $pattern) {
    foreach ($a in $obj.GetAttributeInfos()) {
        if ($a.Name -match $pattern) {
            $v = try { $obj.GetAttribute($a.Name) } catch { "<$($_.Exception.InnerException.Message)>" }
            "    $($a.Name) [$($a.AccessMode)] = $v"
        }
    }
}
function Show-Compile($result, $indent = '') {
    foreach ($m in $result.Messages) {
        if ($m.State -ne 'Success' -or $indent.Length -lt 4) { "$indent[$($m.State)] $($m.Path): $($m.Description)" }
        Show-Compile $m "$indent  "
    }
}

$scl = @'
DATA_BLOCK "Data block.1"
{ S7_Optimized_Access := 'TRUE' }
VERSION : 0.1
NON_RETAIN
   VAR
      "value.1" : Int;
      plain : Int;
      "arr.x" : Array[0..3] of Int;
      "nested.s" : Struct
         "x.y" : Real;
         z : Bool;
      END_STRUCT;
   END_VAR
BEGIN
   "value.1" := 42;
   plain := 7;
   "arr.x"[2] := 22;
   "nested.s"."x.y" := 1.5;
END_DATA_BLOCK

DATA_BLOCK "Data_block_1"
{ S7_Optimized_Access := 'TRUE' }
VERSION : 0.1
NON_RETAIN
   VAR
      toto : Int;
   END_VAR
BEGIN
   toto := 5;
END_DATA_BLOCK
'@

$tia = New-Object Siemens.Engineering.TiaPortal ([Siemens.Engineering.TiaPortalMode]::WithoutUserInterface)
Log 'TIA started'
try {
    $projDir = Join-Path $Root $ProjectName
    if (Test-Path $projDir) { Remove-Item $projDir -Recurse -Force }
    New-Item -ItemType Directory -Force $Root | Out-Null
    $project = $tia.Projects.Create([IO.DirectoryInfo]$Root, $ProjectName)
    Log "project created: $($project.Path)"
    if ($Introspect) { 'project attrs:'; Show-Attrs $project 'imul|rotect|ecur|ompil' }
    $sim = Svc $project ([Siemens.Engineering.SW.PlcSimulationSettingsProvider])
    $sim.IsSimulationDuringBlockCompilationEnabled = $true
    Log "simulation support during block compilation: $($sim.IsSimulationDuringBlockCompilationEnabled)"

    $device = $project.Devices.CreateWithItem($Cpu, 'PLC_1', 'PLC_1')
    $items = @(All-Items $device.DeviceItems)
    $cpuItem = $items | Where-Object { Svc $_ ([Siemens.Engineering.HW.Features.SoftwareContainer]) } | Select-Object -First 1
    Log "CPU item: $($cpuItem.Name)"
    if ($Introspect) {
        'cpu attrs:'; Show-Attrs $cpuItem 'imul|rotect|ecur|assw|ccess|onfidential|ertif'
        'cpu services:'
        $asms = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { -not $_.IsDynamic -and $_.GetName().Name -like 'Siemens.Engineering*' }
        foreach ($t in $asms.GetExportedTypes() | Where-Object { $_.Namespace -like 'Siemens.Engineering*' -and $_.IsClass -and $_.Name -match 'Secret|Protect|Security|Password|Certificate' }) {
            $s = try { Svc $cpuItem $t } catch { $null }
            if ($s) { "    $($t.FullName)"; $t.GetMethods() | Where-Object DeclaringType -eq $t | ForEach-Object { "      $_" } }
        }
    }

    # Test PLC: no confidential-data password, no access control (full access for everyone).
    $secret = Svc $cpuItem ([Siemens.Engineering.HW.Features.PlcMasterSecretConfigurator])
    if ($secret) { $secret.Unprotect() }
    if ($cpuItem.GetAttributeInfos().Name -contains 'PlcAccessControlConfiguration') {
        $cpuItem.SetAttribute('PlcAccessControlConfiguration', [Siemens.Engineering.HW.PlcAccessControlConfiguration]::Disabled)
    }
    $levels = Svc $cpuItem ([Siemens.Engineering.HW.Features.PlcAccessLevelProvider])
    if ($levels) {
        Log "access level was $($levels.PlcProtectionAccessLevel)"
        $levels.PlcProtectionAccessLevel = [Siemens.Engineering.HW.PlcProtectionAccessLevel]::FullAccess
    }
    Log "security: access level $(if ($levels) { $levels.PlcProtectionAccessLevel } else { 'n/a' }), master secret unprotected=$([bool]$secret), access control $(try { $cpuItem.GetAttribute('PlcAccessControlConfiguration') } catch { 'n/a' })"

    # IP address on the PROFINET interface.
    $node = $null
    foreach ($i in $items) {
        $ni = Svc $i ([Siemens.Engineering.HW.Features.NetworkInterface])
        if ($ni -and $ni.Nodes.Count -gt 0) { $node = $ni.Nodes[0]; break }
    }
    $node.SetAttribute('Address', $Ip)
    $node.SetAttribute('SubnetMask', $Mask)
    [void]$node.CreateAndConnectToSubnet('PN/IE_1')
    Log "IP set: $($node.GetAttribute('Address'))/$($node.GetAttribute('SubnetMask'))"

    # Blocks from an SCL source.
    $plc = (Svc $cpuItem ([Siemens.Engineering.HW.Features.SoftwareContainer])).Software
    $srcFile = Join-Path $Root 'issue1_dbs.scl'
    [IO.File]::WriteAllText($srcFile, $scl, (New-Object Text.UTF8Encoding $true))
    $src = $plc.ExternalSourceGroup.ExternalSources.CreateFromFile('issue1_dbs.scl', $srcFile)
    $src.GenerateBlocksFromSource()
    Log ("blocks: " + (($plc.BlockGroup.Blocks | ForEach-Object { "$($_.Name)(DB$($_.Number))" }) -join ', '))

    # Compile hardware + software.
    $res = (Svc $cpuItem ([Siemens.Engineering.Compiler.ICompilable])).Compile()
    Log "compile: $($res.State) (errors $($res.ErrorCount), warnings $($res.WarningCount))"
    Show-Compile $res
    if ($res.State -eq 'Error') { throw 'compile failed' }
    $project.Save()

    # Download to PLCSIM Advanced over the virtual adapter.
    $dp = Svc $cpuItem ([Siemens.Engineering.Download.DownloadProvider])
    $mode = $dp.Configuration.Modes.Find('PN/IE')
    Log ("PG/PC interfaces: " + (($mode.PcInterfaces | ForEach-Object { "$($_.Name) #$($_.Number)" }) -join '; '))
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
    # Going online: trust the (local PLCSIM) PLC's TLS certificate; log anything else asked.
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
    $project.Save()
    $project.Close()
} finally {
    $tia.Dispose()
}
