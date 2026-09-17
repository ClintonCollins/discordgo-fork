param([string] $Destination = '.native/libdave/windows')

$ErrorActionPreference = 'Stop'
$destinationPath = [IO.Path]::GetFullPath($Destination)
$patch = Join-Path $PSScriptRoot 'libdave-channel-binding.patch'
$revision = '9686fbaea864aa19f0675e486672b6a77811b6a1'
$patchHash = (Get-FileHash -LiteralPath $patch -Algorithm SHA256).Hash.ToLowerInvariant()
$key = "$revision-$patchHash"
$marker = Join-Path $destinationPath 'build-revision.txt'
$pkgconfig = Join-Path $destinationPath 'lib/pkgconfig'
$prepared = (Test-Path -LiteralPath $marker) -and (Test-Path -LiteralPath (Join-Path $pkgconfig 'dave.pc'))
if ($prepared) { $prepared = (Get-Content -LiteralPath $marker -Raw).Trim() -eq $key }
if (-not $prepared) {
    $work = Join-Path (Split-Path -Parent $destinationPath) ('.build-windows-' + $patchHash.Substring(0, 12))
    $source = Join-Path $work 'source'
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    if (-not (Test-Path -LiteralPath $source)) {
        & git -c core.autocrlf=false clone --branch v1.2.0/cpp --depth 1 --recurse-submodules https://github.com/discord/libdave.git $source
        if ($LASTEXITCODE -ne 0) { throw 'Unable to clone libdave' }
    }
    $head = & git -C $source rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $head -ne $revision) { throw 'Unexpected libdave source revision' }
    $vcpkgHead = & git -C "$source/cpp/vcpkg" rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $vcpkgHead -ne '16c71a39e5a0fc0bdb3fad03beef8f38ee00ee3b') { throw 'Unexpected vcpkg source revision' }
    & git -C $source apply --reverse --check $patch 2>$null
    if ($LASTEXITCODE -ne 0) {
        & git -C $source apply $patch
        if ($LASTEXITCODE -ne 0) { throw 'Unable to apply the Welcome channel-binding patch' }
    }
    $env:VCPKG_DISABLE_METRICS = '1'
    $env:VCPKG_DOWNLOADS = Join-Path $work 'downloads'
    $cache = Join-Path (Split-Path -Parent $destinationPath) '.cache'
    $env:VCPKG_BINARY_SOURCES = "clear;files,$cache,readwrite"
    if (-not $env:CMAKE_BUILD_PARALLEL_LEVEL) { $env:CMAKE_BUILD_PARALLEL_LEVEL = '4' }
    if (-not $env:VCPKG_MAX_CONCURRENCY) { $env:VCPKG_MAX_CONCURRENCY = $env:CMAKE_BUILD_PARALLEL_LEVEL }
    New-Item -ItemType Directory -Force -Path $env:VCPKG_DOWNLOADS,$cache | Out-Null
    & "$source/cpp/vcpkg/bootstrap-vcpkg.bat" -disableMetrics
    if ($LASTEXITCODE -ne 0) { throw 'Unable to bootstrap vcpkg' }
    $cmake = 'cmake'
    if ($env:CMAKE) { $cmake = $env:CMAKE }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    $visualStudio = & $vswhere -latest -products '*' -version '[17.0,18.0)' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $visualStudio) { throw 'Visual Studio 2022 C++ build tools are required' }
    $toolset = Get-ChildItem -LiteralPath (Join-Path $visualStudio 'VC/Tools/MSVC') -Directory | Sort-Object { [version] $_.Name } -Descending | Select-Object -First 1
    $env:VCPKG_VISUAL_STUDIO_PATH = $visualStudio
    & $cmake -S "$source/cpp" -B "$work/build" -G 'Visual Studio 17 2022' -A x64 -T ('version=' + $toolset.Name) `
        '-DCMAKE_BUILD_TYPE=Release' '-DVCPKG_TARGET_TRIPLET=x64-windows-static' `
        "-DVCPKG_MANIFEST_DIR=$source/cpp/vcpkg-alts/boringssl" `
        "-DCMAKE_TOOLCHAIN_FILE=$source/cpp/vcpkg/scripts/buildsystems/vcpkg.cmake" `
        '-DBUILD_SHARED_LIBS=ON' '-DREQUIRE_BORINGSSL=ON' '-DTESTING=OFF' `
        '-DINSTALL_VCPKG_LICENSES=ON' '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded' `
        "-DCMAKE_INSTALL_PREFIX=$destinationPath"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to configure libdave' }
    & $cmake --build "$work/build" --config Release --target libdave
    if ($LASTEXITCODE -ne 0) { throw 'Unable to build libdave' }
    & $cmake --install "$work/build" --config Release
    if ($LASTEXITCODE -ne 0) { throw 'Unable to install libdave into the build directory' }
    New-Item -ItemType Directory -Force -Path $pkgconfig | Out-Null
    $pc = @"
prefix=`${pcfiledir}/../..
libdir=`${prefix}/lib
includedir=`${prefix}/include

Name: dave
Description: Discord media encryption with Welcome channel binding
Version: 1.2.0-channel-binding.1
Libs: -L`${libdir} -ldave
Cflags: -I`${includedir}
"@
    [IO.File]::WriteAllText((Join-Path $pkgconfig 'dave.pc'), $pc + "`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($marker, $key + "`n", [Text.UTF8Encoding]::new($false))
}
$env:PKG_CONFIG_PATH = $pkgconfig
$env:CGO_ENABLED = '1'
Write-Host "libdave ready: $destinationPath"
