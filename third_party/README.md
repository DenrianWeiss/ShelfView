# Third-party source inventory

The project's own license remains unspecified. This inventory grants no new
license to project code.

Source dependencies are Git submodules pinned by the parent repository. Run
`git submodule update --init --recursive` before building. SwiftPM and NuGet
continue to manage their platform packages; curl/OpenSSL retain their existing
platform-library and Apple build workflows.

## yyjson

- Source: https://github.com/ibireme/yyjson
- Version: 0.12.0
- Commit: `8b4a38dc994a110abaec8a400615567bd996105f`
- License: MIT, preserved in `yyjson/LICENSE`
- Submodule; CMake compiles upstream `src/yyjson.c` and includes `src/yyjson.h`.
- SHA-256:
  - `yyjson.c`: `ac2e9bbb2e2d9149d90878d40506a1d624fa0b33c979a11b61075c54782c6d6a`
  - `yyjson.h`: `175867c5493a5df648cec566717fa1c29aa2f6096f5f0cf1efad0b65e1f6d7b3`
  - `LICENSE`: `45e384d3d52c73cba3a64d6e6c25d47cd738cd8a55c30629e3201046eda62947`

## CivetWeb

- Upstream: https://github.com/civetweb/civetweb
- Commit: `588860e30721bf5453b0440c390865a8e85dcae5` (1.17 development tree)
- Main HTTP/TLS code: MIT. Internal MD5 uses its retained zlib-style notice;
  SHA-1 is public domain. These do not implement Agent pairing authentication.
  Full upstream license preserved in `civetweb/LICENSE.md` and source notices.
- Exact included-file hashes and local changes: `patches/civetweb/SOURCE.json`, `patches/civetweb/local.patch`.
- CMake copies the required upstream files into the build directory and applies
  the patch there; the submodule remains unmodified. Patch failure stops configuration.
- A local patch repairs the pinned tree's incomplete HTTP-framing variable refactor;
  it does not disable authentication or TLS verification.
- WebSocket patches enforce a pre-allocation frame cap and basic RFC6455 frame
  checks, and expose a socket-shutdown-only helper for pinned server lifetimes.
- No CGI, file serving, Lua, Duktape, SQLite, HTTP/2 or compression is enabled.
- Third-party license is installed with the executable; the project license remains unspecified.

## Platform libraries

The initial build links dynamically to the platform's libcurl (curl permissive
license) and OpenSSL 3 (Apache-2.0). Verified here: Debian libcurl 8.14.1 and
OpenSSL 3.5.7. The curl adapter currently requires the OpenSSL 3 backend;
Schannel/Secure Transport and other backends are not implemented.

CMake uses the installed library packages; it does not download or vendor them.
Platform library transitive dependencies and their distribution obligations must
be reviewed for each shipped package. This is not a completed distribution audit.
The current Debian curl build has optional protocol dependencies absent from a
minimal HTTPS-only build; those are not automatically approved for bundling.

QEMU/OpenBMC firmware are external integration-test tools, not linked product
dependencies or bundled app components. Their licensing and provenance must be
preserved separately if distributing a test environment.

## Yxml

- Upstream: https://code.blicky.net/yorhel/yxml
- Commit: `66507906673bc6159d5d620414479954c9c21c24`
- License: MIT, preserved unmodified in `yxml/COPYING`.
- `yxml.c` and `yxml.h` are unmodified upstream files, linked statically into the MegaRAC adapter.
- Used for bounded, in-memory JNLP parsing; no network or custom entity resolver.
- Upstream limitations include duplicate-attribute and Unicode validation; the launch wrapper rejects duplicate attributes and restricts protocol argument values.
- SHA-256:
  - `yxml.c`: `7699a9c0e9d9b987b74ff86bf3fc28be6deed062d22d9a0f8376b868b15864e5`
  - `yxml.h`: `6f79158a3811bf1fab575ef512b91ffc87a795f070b562f7fb6bcbf71fdd9078`
  - `COPYING`: `b9b5ca63904b3cf589d5719be2968436550914dc3fdf5d81b37ddbdd67986d06`

## libjpeg-turbo

- Upstream: https://github.com/libjpeg-turbo/libjpeg-turbo
- Version: 3.1.4.1, commit `9217719d3a58633923b096af4c1d50d304768a64`
- Pinned submodule, built as a static library in the task/build directory using
  upstream CMake. No system JPEG dependency or runtime download is required.
- Used by the bounded RFB Tight/JPEG decoder; RGBA output is byte ordered.
- License terms are preserved in `libjpeg-turbo/LICENSE.md` and
  `libjpeg-turbo/README.ijg`, installed under `share/licenses/bcontrol/libjpeg-turbo`.
