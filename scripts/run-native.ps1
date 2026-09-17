param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Executable,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $ProgramArguments
)

$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $Executable).Path
$pkgConfig = 'pkg-config'
if ($env:PKG_CONFIG) { $pkgConfig = $env:PKG_CONFIG }
$libraryDirectory = & $pkgConfig --variable=prefix dave
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$source = Join-Path $libraryDirectory 'bin/libdave.dll'
$destination = Join-Path (Split-Path -Parent $target) 'libdave.dll'
if (Test-Path -LiteralPath $destination) {
    if ((Get-FileHash -LiteralPath $source).Hash -ne (Get-FileHash -LiteralPath $destination).Hash) {
        throw "An incompatible libdave.dll already exists beside $target. Use a fresh build directory."
    }
} else {
    Copy-Item -LiteralPath $source -Destination $destination
}
& $target @ProgramArguments
exit $LASTEXITCODE
