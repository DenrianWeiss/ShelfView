# Windows/Linux Desktop Client



| Package | Version | License | Note |
| --- | --- | --- | --- |
| Avalonia / Avalonia.Desktop / Avalonia.Themes.Fluent | 12.0.4 | MIT | UI |
| Iciclecreek.Avalonia.Terminal | 4.1.0 | MIT | SOL Terminal with `AttachConnection` |
| Porta.Pty | 2.2.3 | MIT | `IPtyConnection` |
| XTerm.NET | 3.0.0 | MIT | Terminal Simulater |
| SkiaSharp.HarfBuzz | 3.119.4 | MIT | Font Rendering |
| Unicode.net | 2.0.0 | MIT | Font Width |
| Wcwidth | 4.0.1 | MIT | Font Width |
| xunit / xunit.runner.visualstudio / Microsoft.NET.Test.Sdk | 2.9.2 / 2.8.2 / 17.11.1 | Apache-2.0 / Apache-2.0 / MIT | Testing |

.NET SDK 10.0.x

## Building

Build C Library First:

```sh
# Windows (prepare libcurl/openssl with vcpkg)
cmake -S . -B build-windows-desktop -G "Visual Studio 17 2022" -A x64 \
  -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-windows -DBC_BUILD_AGENT=OFF -DBUILD_TESTING=OFF
cmake --build build-windows-desktop --config Release

# Linux/WSL
cmake -S . -B build-wsl-desktop -G Ninja -DBC_BUILD_AGENT=OFF -DBUILD_TESTING=OFF
cmake --build build-wsl-desktop
```

Then build the shell application `-p:BControlNativeDir=`

```sh
cd frontends/desktop
dotnet build src/BControl.Desktop/BControl.Desktop.csproj
```
