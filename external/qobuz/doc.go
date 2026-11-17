// Package qobuz implements a cliamp music provider for Qobuz.
//
// It authenticates via the interactive OAuth browser flow, scrapes the
// app_id / signing secrets / OAuth private key from the Qobuz web player
// bundle.js, and gives tracks qobuz://track/<id> paths. When a track starts,
// ResolveSource opens a qbz-1 session (session/start + file/url), then
// downloads the CMAF segments and decrypts their AES-128-CTR FLAC frames
// (cmaf.go). Qobuz retired the legacy track/getFileUrl endpoint with HTTP 410.
// The decrypted FLAC bytes go through cliamp's buffer-while-playing + ffmpeg
// pipeline (see the Reader source that providers.go registers), the same
// path used by the Tidal, Navidrome, Jellyfin, Emby and Plex providers.
//
// Source material consulted for the reverse-engineered API surface:
//
//   - Aeneaj/qobuz-dl-go: Go client (primary template for signing,
//     bundle scraping and OAuth).
//   - DashLt/spoofbuz: secret/seed extraction from bundle.js.
//   - SofusA/qobine, qobuz-player-controls/examples/qobuz-api.md: a
//     comprehensive reverse-engineered Qobuz API reference used to
//     cross-check signing, the OAuth flow, format IDs and the
//     legacy-vs-segmented (/file/url) streaming distinction.
package qobuz
