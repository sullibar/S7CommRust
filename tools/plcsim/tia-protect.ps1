# Set the CPU's access protection in a TIA V21 project: the access level that needs no password
# (FullAccess, ReadAccess, HMIAccess or NoAccess) and the password for full access. Compiles and
# saves; download with tia-download.ps1 (once the PLC is protected, pass it -Password). See
# README.md. The level must be below FullAccess before a full-access password can be set.
param(
    [Parameter(Mandatory)][string]$ProjectPath,
    [Parameter(Mandatory)][string]$Level,
    [Parameter(Mandatory)][string]$FullAccessPassword
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
    $device = $project.Devices | Select-Object -First 1
    $cpuItem = @(All-Items $device.DeviceItems) | Where-Object { Svc $_ ([Siemens.Engineering.HW.Features.SoftwareContainer]) } | Select-Object -First 1
    $levels = Svc $cpuItem ([Siemens.Engineering.HW.Features.PlcAccessLevelProvider])
    Log "access level was $($levels.PlcProtectionAccessLevel)"
    $levels.PlcProtectionAccessLevel = [Enum]::Parse([Siemens.Engineering.HW.PlcProtectionAccessLevel], $Level)
    $levels.SetPassword([Siemens.Engineering.HW.PlcProtectionAccessLevel]::FullAccess, (Secure $FullAccessPassword))
    Log "access level now $($levels.PlcProtectionAccessLevel), full-access password set"
    $res = (Svc $cpuItem ([Siemens.Engineering.Compiler.ICompilable])).Compile()
    Log "compile: $($res.State) (errors $($res.ErrorCount), warnings $($res.WarningCount))"
    if ($res.State -eq 'Error') { throw 'compile failed' }
    $project.Save()
    $project.Close()
    Log 'saved'
} finally {
    $tia.Dispose()
}
