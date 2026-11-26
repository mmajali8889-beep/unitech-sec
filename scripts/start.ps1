<# Local start (API on 127.0.0.1 only + restricted agent). Not exposed to the network. #>
param([Parameter(Mandatory=$true)][string[]]$ApprovedRoot, [int]$Port = 8787, [string]$DataDir = "$PSScriptRoot\..\data")
$root = Resolve-Path "$PSScriptRoot\.."
$args = @("$root\scripts\start_local.py", "--data-dir", $DataDir, "--port", $Port)
foreach ($r in $ApprovedRoot) { $args += @("--approved-root", $r) }
& "$root\.venv\Scripts\python.exe" @args
