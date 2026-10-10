[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$Revision)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
& .\check.ps1
if ($LASTEXITCODE) { throw 'Verification failed' }
$feed = Join-Path $PSScriptRoot 'artifacts\packages'
New-Item -ItemType Directory -Force $feed | Out-Null
foreach ($project in @('src\Yukat.UpdateVerify', 'src\Yukat.UpdateVerify.Cli')) {
    & dotnet pack $project -c Release --no-build -o $feed "-p:RepositoryCommit=$Revision" "-p:SourceRevisionId=$Revision"
    if ($LASTEXITCODE) { throw "Packing failed: $project" }
}
$config = Join-Path $PSScriptRoot 'artifacts\local-feed.config'
$escapedFeed = [Security.SecurityElement]::Escape($feed)
[IO.File]::WriteAllText($config, "<configuration><packageSources><clear/><add key=`"local-reviewed`" value=`"$escapedFeed`"/></packageSources></configuration>")
& dotnet restore examples\MinimalApp --configfile $config --packages artifacts\sample-packages
if ($LASTEXITCODE) { throw 'Example did not restore the packed NuGet library' }
& dotnet run --project examples\MinimalApp -c Release --no-restore -- artifacts\example\fresh-manifest.json artifacts\example\trusted-public.pem artifacts\example\package.bin updates.example.org
if ($LASTEXITCODE) { throw 'Packaged library example failed' }
$tool = Join-Path $PSScriptRoot 'artifacts\tool'
& dotnet tool install Yukat.UpdateVerify.Tool --version 0.2.0 --tool-path $tool --configfile $config
if ($LASTEXITCODE) { throw 'Local NuGet tool installation failed' }
& (Join-Path $tool 'yukat-update-verify.exe') --fresh artifacts\example\fresh-manifest.json artifacts\example\trusted-public.pem artifacts\example\package.bin updates.example.org
if ($LASTEXITCODE) { throw 'Installed NuGet tool failed' }
$payload = Join-Path $PSScriptRoot 'artifacts\example\package.bin'
$original = [IO.File]::ReadAllBytes($payload)
try {
    $damaged = [byte[]]$original.Clone(); $damaged[0] = $damaged[0] -bxor 1
    [IO.File]::WriteAllBytes($payload, $damaged)
    $ErrorActionPreference = 'Continue'
    & dotnet run --project examples\MinimalApp -c Release --no-build -- artifacts\example\fresh-manifest.json artifacts\example\trusted-public.pem artifacts\example\package.bin updates.example.org
    if ($LASTEXITCODE -ne 1) { throw 'NuGet example accepted a damaged package' }
} finally { $ErrorActionPreference = 'Stop'; [IO.File]::WriteAllBytes($payload, $original) }
$packages = @(Get-ChildItem $feed -File | ForEach-Object { @{name=$_.Name; sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); size=$_.Length} })
@{revision=$Revision; version='0.2.0'; checkedAtUtc=[DateTime]::UtcNow.ToString('o'); tests=56; cliCases=5; packageExample='passed'; installedTool='passed'; damagedPackage='rejected'; packages=$packages} |
    ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 artifacts\release-receipt.json
