# Add a Program_Alarm (FB + instance DB + trigger DB + OB1 call) to an existing TIA V21 project,
# compile and save it. Download separately with tia-download.ps1.
param([Parameter(Mandatory)][string]$ProjectPath, [Parameter(Mandatory)][string]$SclPath)
$ErrorActionPreference = 'Stop'
$d = "C:\Program Files\Siemens\Automation\Portal V21\PublicAPI\V21\net48"
Get-ChildItem "$d\Siemens.Engineering*.dll" | ForEach-Object { [void][Reflection.Assembly]::LoadFrom($_.FullName) }
function Log($m) { "$(Get-Date -Format HH:mm:ss) $m" }
function Svc($obj, [type]$t) {
    [Siemens.Engineering.IEngineeringServiceProvider].GetMethod('GetService').MakeGenericMethod($t).Invoke($obj, $null)
}
function All-Items($items) { foreach ($i in $items) { $i; All-Items $i.DeviceItems } }
function Show-Compile($result, $indent = '') {
    foreach ($m in $result.Messages) {
        if ($m.State -ne 'Success' -or $indent.Length -lt 4) { "$indent[$($m.State)] $($m.Path): $($m.Description)" }
        Show-Compile $m "$indent  "
    }
}
$tia = New-Object Siemens.Engineering.TiaPortal ([Siemens.Engineering.TiaPortalMode]::WithoutUserInterface)
Log 'TIA started'
try {
    $project = $tia.Projects.Open([IO.FileInfo]$ProjectPath)
    $device = $project.Devices | Select-Object -First 1
    $cpuItem = @(All-Items $device.DeviceItems) | Where-Object { Svc $_ ([Siemens.Engineering.HW.Features.SoftwareContainer]) } | Select-Object -First 1
    $plc = (Svc $cpuItem ([Siemens.Engineering.HW.Features.SoftwareContainer])).Software
    Log ("blocks before: " + (($plc.BlockGroup.Blocks | ForEach-Object { $_.Name }) -join ', '))
    $existing = $plc.ExternalSourceGroup.ExternalSources.Find('alarms.scl')
    if ($existing) { $existing.Delete() }
    $src = $plc.ExternalSourceGroup.ExternalSources.CreateFromFile('alarms.scl', $SclPath)
    $src.GenerateBlocksFromSource()
    Log ("blocks after: " + (($plc.BlockGroup.Blocks | ForEach-Object { $_.Name }) -join ', '))
    $res = (Svc $cpuItem ([Siemens.Engineering.Compiler.ICompilable])).Compile()
    Log "compile: $($res.State) (errors $($res.ErrorCount), warnings $($res.WarningCount))"
    Show-Compile $res
    if ($res.State -eq 'Error') { throw 'compile failed' }
    $project.Save()
    $project.Close()
    Log 'saved'
} finally {
    $tia.Dispose()
}
