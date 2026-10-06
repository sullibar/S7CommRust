# Keeps a PLCSIM Advanced instance alive: API-registered instances are owned by the registering
# process and vanish when it exits (and on a reboot). Start it hidden, then download a project:
#   Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-File','tools\plcsim\plcsim-host.ps1'
# Stop it by creating the file named in $StopFile.
param(
    [string]$Name = 'S7CommRust',
    [string]$Ip = '169.254.130.10',
    [string]$Mask = '255.255.0.0',
    [string]$Log = "$env:TEMP\s7plcsim\plcsim-host.log",
    [string]$StopFile = "$env:TEMP\s7plcsim\plcsim-host.stop"
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force (Split-Path $Log) | Out-Null
Remove-Item $StopFile -ErrorAction SilentlyContinue
function Log($m) { "$(Get-Date -Format s) $m" | Out-File $Log -Append -Encoding utf8 }
try {
    Add-Type -Path "C:\Program Files (x86)\Common Files\Siemens\PLCSIMADV\API\8.0\Siemens.Simatic.Simulation.Runtime.Api.x64.dll"
    $M = [Siemens.Simatic.Simulation.Runtime.SimulationRuntimeManager]
    if ($M::NetworkMode -ne 'TCPIPSingleAdapter') { $M::NetworkMode = 'TCPIPSingleAdapter' }
    $inst = $M::RegisterInstance([Siemens.Simatic.Simulation.Runtime.ECPUType]::CPU1500_Unspecified, $Name)
    Log "registered '$Name': PowerOn $($inst.PowerOn(60000))"
    $suite = New-Object Siemens.Simatic.Simulation.Runtime.SIPSuite4 -ArgumentList $Ip, $Mask, '0.0.0.0'
    $inst.SetIPSuite(0, $suite, $true)
    Log "state=$($inst.OperatingState) ip=$($inst.ControllerIP -join ',')"
    while (-not (Test-Path $StopFile)) { Start-Sleep -Seconds 2 }
    Log 'stop requested'
    $inst.PowerOff(60000)
    $inst.UnregisterInstance()
    Log 'unregistered'
} catch {
    Log "ERROR: $_"
}
