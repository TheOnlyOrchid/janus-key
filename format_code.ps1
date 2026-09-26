# nice little formatting script
$projectRoot = $PSScriptRoot
$files = Get-ChildItem -Path (Join-Path $projectRoot 'src'), (Join-Path $projectRoot 'tests') `
    -Recurse -File -Include *.c, *.cc, *.cpp, *.h, *.hh, *.hpp

foreach ($file in $files) {
    & clang-format -i $file.FullName
    if ($LASTEXITCODE -ne 0) {
        throw "clang-format failed for $($file.FullName)"
    }
}

$spacingScript = Join-Path $projectRoot 'tools\format_control_blocks.py'
& python $spacingScript --root $projectRoot
if ($LASTEXITCODE -ne 0) {
    throw 'spacing failed'
}
