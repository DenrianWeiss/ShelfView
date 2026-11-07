param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("x64", "arm64")]
    [string]$Architecture,
    [string]$VcpkgRoot = $env:VCPKG_ROOT,
    [string]$Dist = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "../../../..")).Path "dist")
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "../../../..")).Path
$triplet = if ($Architecture -eq "arm64") { "arm64-windows" } else { "x64-windows" }
$rid = if ($Architecture -eq "arm64") { "win-arm64" } else { "win-x64" }
$build = Join-Path $root "build-windows-$Architecture-desktop"
$native = Join-Path $build "Release"
$publish = Join-Path $Dist "windows-$Architecture"

if (-not $VcpkgRoot -or -not (Test-Path (Join-Path $VcpkgRoot "scripts/buildsystems/vcpkg.cmake"))) {
    throw "Set VCPKG_ROOT to a vcpkg checkout that provides curl and OpenSSL."
}
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) { throw "CMake is required." }
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw ".NET 10 SDK is required." }

& (Join-Path $VcpkgRoot "vcpkg.exe") install "curl[openssl]:$triplet" "openssl:$triplet"
if ($LASTEXITCODE -ne 0) { throw "vcpkg dependency installation failed." }

$vsArch = if ($Architecture -eq "arm64") { "ARM64" } else { "x64" }
cmake -S $root -B $build -G "Visual Studio 17 2022" -A $vsArch `
    "-DCMAKE_TOOLCHAIN_FILE=$(Join-Path $VcpkgRoot 'scripts/buildsystems/vcpkg.cmake')" `
    "-DVCPKG_TARGET_TRIPLET=$triplet" -DBC_BUILD_AGENT=OFF -DBUILD_TESTING=OFF
if ($LASTEXITCODE -ne 0) { throw "CMake configuration failed." }
cmake --build $build --config Release
if ($LASTEXITCODE -ne 0) { throw "Native build failed." }

if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }
New-Item -ItemType Directory -Force -Path $publish | Out-Null
dotnet publish (Join-Path $root "frontends/desktop/src/BControl.Desktop/BControl.Desktop.csproj") `
    -c Release -r $rid --self-contained true -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true `
    "-p:BControlNativeDir=$native" -p:BControlSignBuildOutput=false -o $publish
if ($LASTEXITCODE -ne 0) { throw "Desktop publish failed." }

# The P/Invoke libraries are copied beside ShelfView.exe so Windows can load them
# using its normal application-directory search, including on clean machines.
Get-ChildItem $native -Filter *.dll | Copy-Item -Destination $publish -Force
Get-ChildItem (Join-Path $VcpkgRoot "installed/$triplet/bin") -Filter *.dll -ErrorAction SilentlyContinue |
    Copy-Item -Destination $publish -Force
if (-not (Test-Path (Join-Path $publish "ShelfView.exe"))) { throw "ShelfView.exe was not produced." }
$licenses = Join-Path $publish 'Licenses'
New-Item -ItemType Directory -Force -Path $licenses | Out-Null
Copy-Item (Join-Path $root 'third_party/pack200/LICENSE.txt') (Join-Path $licenses 'Pack200.txt') -Force
Copy-Item (Join-Path $root 'docs/pack200-dependency.txt') (Join-Path $licenses 'Pack200-SOURCE.txt') -Force
Copy-Item (Join-Path $root 'third_party/libjpeg-turbo/LICENSE.md') (Join-Path $licenses 'libjpeg-turbo.txt') -Force
Copy-Item (Join-Path $root 'third_party/libjpeg-turbo/README.ijg') (Join-Path $licenses 'libjpeg-ijg.txt') -Force
Write-Host "Self-contained package: $publish"
