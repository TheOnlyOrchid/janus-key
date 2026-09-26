param([Parameter(Mandatory)][string]$Build, [Parameter(Mandatory)][string]$Root,
      [Parameter(Mandatory)][string]$Runner)
$ErrorActionPreference = 'Stop'
$Build = [IO.Path]::GetFullPath($Build)
$Root = [IO.Path]::GetFullPath($Root)
$suite = Join-Path $Build ('capture-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $suite | Out-Null
foreach ($mode in @('xpress', 'none', 'fault', 'rep', 'limited', 'pressure', 'all')) {
    $directory = Join-Path $suite $mode
    New-Item -ItemType Directory -Path $directory | Out-Null
    $codec = if ($mode -eq 'none') { 'none' } else { 'xpress' }
    $cap = if ($mode -eq 'limited') { '4' } else { '4294967295' }
    $oracle = Join-Path $directory 'oracle.txt'
    $arguments = @('-t', "$Build/janus_key_pintool.dll", '-o', $directory, '-scope', 'main', '-registers', '1', '-compression', $codec, '-max_memory_bytes', $cap, '-follow_children', '0', '--', $Runner, '--capture-coverage-target', $oracle, '5000')
    if ($mode -in @('fault', 'rep')) { $arguments += $mode }
    if ($mode -eq 'pressure') { $arguments = $arguments[0..1] + @('-writer_queue_mb', '1') + $arguments[2..($arguments.Length-1)] }
    if ($mode -eq 'all') { $arguments[$arguments.IndexOf('-scope') + 1] = 'all' }
    & "$Root/third_party/pin/pin.exe" @arguments
    if ($LASTEXITCODE -ne 0) { throw "Capture failed: $mode" }
    $trace = Join-Path $directory 'trace.jkt'
    $report = Join-Path $directory 'coverage.json'
    & $Runner --capture-coverage-validation $trace $oracle $report
    $validationExit = $LASTEXITCODE
    $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
    if ($mode -eq 'limited') {
        if ($validationExit -eq 0 -or $result.diagnostics.memory_capture_limit -le 0) { throw 'Capture limit was not detected' }
    } elseif ($validationExit -ne 0) { throw "Coverage failed: $mode ($report)" }
    $writer = Get-Content (Join-Path $directory 'writer-performance.json') -Raw | ConvertFrom-Json
    if ($writer.storage_failed -or $writer.completed_blocks -le 0) { throw "Background writer failed: $mode" }
    if ($mode -eq 'pressure' -and $writer.backpressure_count -le 0) { throw 'Backpressure path was not exercised' }
    if ($mode -eq 'none') {
        $bytes = [IO.File]::ReadAllBytes($trace)
        $bytes[60] = $bytes[60] -bxor 64
        $damaged = Join-Path $directory 'corrupt.jkt'
        [IO.File]::WriteAllBytes($damaged, $bytes)
        & $Runner --capture-coverage-validation $damaged $oracle $report
        if ($LASTEXITCODE -eq 0 -or -not (Get-Content $report -Raw | ConvertFrom-Json).corrupt) { throw 'Corruption was not reported' }
        $bytes = [IO.File]::ReadAllBytes($trace)
        $truncated = Join-Path $directory 'truncated.jkt'
        [IO.File]::WriteAllBytes($truncated, $bytes[0..($bytes.Length-2)])
        & $Runner --capture-coverage-validation $truncated $oracle $report
        if ($LASTEXITCODE -eq 0 -or -not (Get-Content $report -Raw | ConvertFrom-Json).incomplete) { throw 'Incomplete capture was not reported' }
    }
}
$registerDirectory = Join-Path $suite 'registers'
New-Item -ItemType Directory -Path $registerDirectory | Out-Null
& "$Root/third_party/pin/pin.exe" -t "$Build/janus_key_pintool.dll" -o $registerDirectory -scope all -follow_children 0 -- $Runner --register-capture-target "$registerDirectory/oracle.txt"
if ($LASTEXITCODE -ne 0) { throw 'Register target capture failed' }
& $Runner --register-capture-validation "$registerDirectory/trace.jkt" "$registerDirectory/oracle.txt"
if ($LASTEXITCODE -ne 0) { throw 'Register capture oracle failed' }
Write-Host "Capture oracle and negative tests passed. Reports: $suite"
exit 0
