# Import SCL sources into an existing TIA V21 project, in order, generating their blocks
# (replacing blocks of the same name); then compile and save. Download separately with
# tia-download.ps1. See README.md.
param(
    [Parameter(Mandatory)][string]$ProjectPath,
    [Parameter(Mandatory)][string[]]$SclPath
)
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
    foreach ($path in $SclPath) {
        $name = Split-Path $path -Leaf
        $existing = $plc.ExternalSourceGroup.ExternalSources.Find($name)
        if ($existing) { $existing.Delete() }
        $src = $plc.ExternalSourceGroup.ExternalSources.CreateFromFile($name, (Resolve-Path $path).Path)
        $src.GenerateBlocksFromSource()
        Log "imported $name"
    }
    Log ("blocks: " + (($plc.BlockGroup.Blocks | ForEach-Object { "$($_.Name) ($($_.Number))" }) -join ', '))
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
