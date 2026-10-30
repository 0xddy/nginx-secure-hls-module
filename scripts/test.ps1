param([string]$Proxy = 'http://127.0.0.1:10886')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$cachePath = Join-Path $projectRoot '.cache'
$outputPath = Join-Path $projectRoot '.build'
New-Item -ItemType Directory -Force $cachePath, $outputPath | Out-Null
foreach ($line in Get-Content (Join-Path $PSScriptRoot 'sources.sha256')) {
    $parts = $line -split '\s+'
    $archiveName = $parts[1]
    $archivePath = Join-Path $cachePath $archiveName
    if (!(Test-Path -LiteralPath $archivePath)) {
        $origin = if ($archiveName.StartsWith('openresty-')) { 'https://openresty.org/download' } else { 'https://nginx.org/download' }
        $curlArgs = @('--fail', '--location', '--retry', '2', "$origin/$archiveName", '-o', $archivePath)
        if ($Proxy) { $curlArgs = @('--proxy', $Proxy) + $curlArgs }
        & curl.exe @curlArgs
        if ($LASTEXITCODE -ne 0) { throw "Download failed: $archiveName" }
    }
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $parts[0]) {
        throw "Archive checksum mismatch: $archiveName"
    }
}
$buildArgs = @('build', '-t', 'secure-hls-dev:local')
if ($Proxy) {
    $dockerProxy = $Proxy.Replace('127.0.0.1', 'host.docker.internal').Replace('localhost', 'host.docker.internal')
    $buildArgs += @('--build-arg', "HTTP_PROXY=$dockerProxy", '--build-arg', "HTTPS_PROXY=$dockerProxy")
}
& docker @buildArgs $projectRoot
if ($LASTEXITCODE -ne 0) { throw 'Docker image build failed' }
& docker volume create secure-hls-build | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker volume creation failed' }
& docker run --rm `
    --mount "type=bind,source=$projectRoot,target=/src,readonly" `
    --mount 'type=volume,source=secure-hls-build,target=/work' `
    --mount "type=bind,source=$outputPath,target=/artifacts" `
    -e HLS_ARTIFACT_ROOT=/artifacts secure-hls-dev:local
if ($LASTEXITCODE -ne 0) { throw 'Build/test matrix failed; see the test output' }
