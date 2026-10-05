# PLCSIM test rig

The live tests in [`tests/live.rs`](../../tests/live.rs) run against a simulated CPU 1511 in
**PLCSIM Advanced**, with a test project built by **TIA Portal V21** through its Openness API.
Everything here is Windows-only, needs both products installed, and the user must be in the
"Siemens TIA Openness" group. Run the scripts from Windows PowerShell 5.1.

## The simulated PLC

A PLCSIM Advanced instance named `S7CommRust` at **169.254.130.10/16** on the "Siemens PLCSIM
Virtual Ethernet Adapter" (network mode `TCPIPSingleAdapter`). The host side of the adapter has an
APIPA address in the same /16, so no host configuration is needed. An instance belongs to the
process that registered it and disappears when that process exits, so register it from a
long-running PowerShell.

The PLCSIM API can also switch the CPU between RUN and STOP:

```powershell
Add-Type -Path "C:\Program Files (x86)\Common Files\Siemens\PLCSIMADV\API\3.0\Siemens.Simatic.Simulation.Runtime.Api.x64.dll"
$plc = [Siemens.Simatic.Simulation.Runtime.SimulationRuntimeManager]::CreateInterface("S7CommRust")
$plc.OperatingState; $plc.Stop(30000); $plc.Run(30000)
```

## The test projects

Two projects, one per connection path; downloading one replaces the other on the simulator.

| Project | CPU | Path | Contents |
|---|---|---|---|
| TLS | 6ES7 511-1AK02-0AB0, FW V2.9 | `Connection::connect` | everything below |
| Legacy | 6ES7 511-1AK02-0AB0, FW V2.8 | `Connection::connect_legacy` | `"Data block.1"`, `Data_block_1` |

Both have full access (no password) and these optimized blocks, created by `tia-build.ps1`:
DB1 `"Data block.1"` (`"value.1"`, `plain`, `"arr.x"`, `"nested.s"`) and DB2 `Data_block_1`
(`toto`). The TLS project adds, from the sources in [`s7commrusttest/`](s7commrusttest) and
[`alarms.scl`](alarms.scl):

| Block | Source | What for |
|---|---|---|
| UDT `"UDT.1"`, FB `"FB.1"` | `types.scl` | a UDT and an FB to instantiate |
| DB3 (a name with every awkward character) | `odd.scl` | quoting in symbol paths |
| DB4 `"Types DB"` | `typesdb.scl` | one member per datatype |
| DB5 `"Std DB"` | `stddb.scl` | a **standard** (not optimized) block, for byte-offset access |
| DB6 `"UDT based DB"`, DB7 `"Inst DB"`, DB8 `"Array DB"` | `udtdb.scl`, `instdb.scl`, `arraydb.scl` | UDT, instance and array DBs |
| FB `"AlarmFB"`, DB9 `"AlarmDB"`, DB10 `"AlarmFB_DB"`, OB1 `"Main"` | `alarms.scl` | a `Program_Alarm` raised by `"AlarmDB".trig`, with `"AlarmDB".val` as SD_1 |

## Building and switching

```powershell
cd tools\plcsim
# TLS project: create, download, then add the blocks and download again.
.\tia-build.ps1 -ProjectName S7CommRustTest
$p = "$env:TEMP\s7plcsim\S7CommRustTest\S7CommRustTest.ap21"
$scl = @('types','odd','typesdb','stddb','udtdb','instdb','arraydb' | % { "s7commrusttest\$_.scl" }) + 'alarms.scl'
.\tia-import-scl.ps1 -ProjectPath $p -SclPath $scl
.\tia-download.ps1 -ProjectPath $p

# Legacy project.
.\tia-build.ps1 -ProjectName S7Legacy -Cpu 'OrderNumber:6ES7 511-1AK02-0AB0/V2.8'

# Switch the simulator to an existing project (about a minute).
.\tia-download.ps1 -ProjectPath "$env:TEMP\s7plcsim\S7Legacy\S7Legacy.ap21"
```

Importing the sources in that order gives the DB numbers above. The TLS steps were last run end
to end on 2026-10-03, and the result passes the live suite; the legacy project was built the same
way. (The project the TLS tests were first written against also has a few PLC tags in its tag
table, so browsing it lists 191 names instead of 185; the tests don't depend on them.)

Gotchas: TIA Openness refuses project paths longer than 143 characters, so keep `$env:TEMP`
short or pass `-Root`. A new CPU's default access level rejects S7CommPlus sessions;
`tia-build.ps1` sets full access, removes the master-secret protection, and trusts the
simulator's TLS certificate when downloading. A headless TIA Portal takes about 20 seconds to
start, and each script starts one.

For the password and program-change checks, work on a copy of the TLS project so the live
suite's project stays unprotected:

```powershell
# Password login: no access without a password, full access with one.
.\tia-protect.ps1 -ProjectPath $copy -Level NoAccess -FullAccessPassword '<test password>'
.\tia-download.ps1 -ProjectPath $copy                       # PLC still unprotected
.\tia-download.ps1 -ProjectPath $other -Password '<test password>'  # any later download

# Program change in RUN: add a new block to the project, then download only the change.
.\tia-import-scl.ps1 -ProjectPath $copy -SclPath new_db.scl
.\tia-download.ps1 -ProjectPath $copy -ChangesOnly -NoStop
```

A download in RUN works for new blocks; a change to an existing block's interface needs
reinitialization, which stops the CPU (and drops every session) unless the block's memory
reserve was activated, which Openness can't do. At "Read access" the PLC still accepts tag writes
from an S7CommPlus client; "No access" is the level where reads and writes need the password.

## Running the live tests

```sh
S7_PLC_IP=169.254.130.10 cargo test --test live -- --ignored            # TLS project loaded
S7_PLC_IP=169.254.130.10 S7_LEGACY=1 cargo test --test live -- --ignored # legacy project loaded
```

Tests that need the TLS project (the standard block, certificate pinning, the alarm) report
themselves as skipped on the legacy one. `S7_LIVE_SOAK=<n>` sets how many connections the soak
test makes (default 25). The tests restore every value they change, but the simulator is shared:
don't switch projects or stop the CPU while another session uses it.
