# DiscordGo fork

This fork maintains Zaku's voice playback support on top of
[yeongaori/discordgo-fork](https://github.com/yeongaori/discordgo-fork), derived from
[bwmarrin/discordgo](https://github.com/bwmarrin/discordgo).

Requires Go 1.26.8 or newer, a C compiler, `pkg-config`, and `CGO_ENABLED=1`.
The module path remains `github.com/bwmarrin/discordgo`; applications select this
fork with a Go module replacement.

Voice joins and disconnects accept a context. Call `WaitForDAVEReady(ctx)` before
starting playback to wait for negotiated media encryption. The sender drops audio
while DAVE is unavailable and never falls back to plaintext after an encryption
error. Callers must stop sending before closing a voice connection; `Dead` signals
that the connection has ended. Do not close `OpusSend` or `OpusRecv` yourself.

DAVE encryption and MLS membership changes use Discord's official
[libdave v1.2.0](https://github.com/discord/libdave/releases/tag/v1.2.0%2Fcpp), built
with the included Welcome channel-binding patch. This replaces the partial MLS
engine with authenticated Welcome, proposal, and commit processing. The patch
rejects a Welcome for a different voice channel; a required exported symbol
prevents accidentally linking an unpatched upstream library. Real multi-member
Discord session validation remains necessary before treating the integration
as fully interoperable.

## Native dependency

The setup helpers build pinned libdave source and its pinned vcpkg dependencies
inside `.native/`; they do not install system libraries. The initial build takes
several minutes. Later builds reuse the local dependency cache. The native build
revision includes the source commit and patch digest.

On Linux x64, install GCC/G++, CMake, Git, `pkg-config`, `curl`, `zip`, `unzip`, and
NASM, then run:

```sh
bash scripts/prepare-libdave.sh
export CGO_ENABLED=1
export PKG_CONFIG_PATH="$PWD/.native/libdave/linux/lib/pkgconfig"
export LD_LIBRARY_PATH="$PWD/.native/libdave/linux/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
go test -race ./...
go vet ./...
golangci-lint run
```

On Windows x64, install Visual Studio 2022 C++ build tools and CMake for libdave,
plus MinGW-w64 GCC and a working `pkg-config` for Go. Put Git, CMake, GCC, and
pkg-config on `PATH`, then run from PowerShell:

```powershell
./scripts/prepare-libdave.ps1
$runner = (Resolve-Path scripts/run-native.ps1).Path
go test -race -exec ('powershell -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $runner) ./...
go vet ./...
golangci-lint run
```

The PowerShell setup configures `CGO_ENABLED` and `PKG_CONFIG_PATH` for that
process. `CMAKE` and `PKG_CONFIG` can name alternate executables. The runner
copies `libdave.dll` beside each test executable and refuses to replace an
incompatible DLL.

To cross-compile Go for Windows on Linux, first build the native library on
Windows and copy its complete installation directory to
`.native/libdave/windows`. With `gcc-mingw-w64-x86-64` installed, run:

```sh
GOOS=windows CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
  PKG_CONFIG_PATH="$PWD/.native/libdave/windows/lib/pkgconfig" go build ./...
```

CI builds both native installations before testing and cross-compiling Go.
Applications must distribute the matching `libdave.dll` or `libdave.so`, plus all
files from the installation's `licenses/` directory. On Linux, link with an
`$ORIGIN` runpath or set `LD_LIBRARY_PATH` to the library directory. The tests
exercise local websocket and UDP peers without a Discord account.
