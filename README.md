# DiscordGo fork

This fork maintains Zaku's voice playback support on top of
[yeongaori/discordgo-fork](https://github.com/yeongaori/discordgo-fork), derived from
[bwmarrin/discordgo](https://github.com/bwmarrin/discordgo).

Requires Go 1.26.8 or newer. The module path remains `github.com/bwmarrin/discordgo`;
applications select this fork with a Go module replacement.

Voice joins and disconnects accept a context. Call `WaitForDAVEReady(ctx)` before
starting playback to wait for negotiated media encryption. The sender drops audio
while DAVE is unavailable and never falls back to plaintext after an encryption
error. Callers must stop sending before closing a voice connection; `Dead` signals
that the connection has ended. Do not close `OpusSend` or `OpusRecv` yourself.

The fork still uses a partial MLS implementation. It does not process membership
commits or perform complete Welcome validation. The existing workaround for
repeated re-Welcome loops is retained, so membership changes can leave obsolete
media keys in use. This update does not establish full DAVE protocol or security
compliance. Resolving that limitation requires replacing or completing the MLS
engine and validating real multi-member Discord sessions.

Run `go test -race ./...`, `go vet ./...`, and `golangci-lint run` before release.
The tests exercise local websocket and UDP peers without a Discord account.
