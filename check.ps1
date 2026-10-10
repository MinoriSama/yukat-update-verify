$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force artifacts | Out-Null
$log = Join-Path $PSScriptRoot 'artifacts\validation.log'
Start-Transcript -Path $log -Force | Out-Null
try {
    & dotnet build src/Yukat.UpdateVerify.Cli -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    & dotnet run --project tests/Yukat.UpdateVerify.Tests -c Release -- --example artifacts/example
    if ($LASTEXITCODE -ne 0) { throw 'Security tests failed' }
    $cli = 'src\Yukat.UpdateVerify.Cli\bin\Release\net8.0\Yukat.UpdateVerify.Cli.dll'
    $baseArgs = @('artifacts/example/manifest.json', 'artifacts/example/trusted-public.pem', 'artifacts/example/package.bin', 'updates.example.org')
    & dotnet $cli @baseArgs '1.2.2'
    if ($LASTEXITCODE -ne 0) { throw 'CLI positive case failed' }
    $ErrorActionPreference = 'Continue'
    & dotnet $cli @baseArgs '1.2.3'
    if ($LASTEXITCODE -ne 1) { throw 'CLI accepted replay or used wrong exit code' }
    & dotnet $cli
    if ($LASTEXITCODE -ne 2) { throw 'CLI usage exit code failed' }
    $package = Join-Path $PSScriptRoot 'artifacts/example/package.bin'
    $original = [IO.File]::ReadAllBytes($package)
    $damaged = [byte[]]$original.Clone()
    $damaged[0] = $damaged[0] -bxor 1
    [IO.File]::WriteAllBytes($package, $damaged)
    try {
        & dotnet $cli @baseArgs
        if ($LASTEXITCODE -ne 1) { throw 'CLI accepted modified package' }
    } finally { [IO.File]::WriteAllBytes($package, $original) }
    $oversize = Join-Path $PSScriptRoot 'artifacts/example/oversize.json'
    [IO.File]::WriteAllBytes($oversize, [byte[]]::new(32769))
    & dotnet $cli $oversize $baseArgs[1] $baseArgs[2] $baseArgs[3]
    if ($LASTEXITCODE -ne 1) { throw 'CLI accepted oversized input' }
    Remove-Item -LiteralPath $oversize
    $ErrorActionPreference = 'Stop'
    Write-Output 'CLI: 5/5 passed'
    @{ checked_at_utc = [DateTime]::UtcNow.ToString('o'); sdk = (& dotnet --version); library_cases = 56; cli_cases = 5; result = 'passed' } |
        ConvertTo-Json | Set-Content -Encoding UTF8 artifacts/validation.json
} finally { Stop-Transcript | Out-Null }
