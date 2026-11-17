package qobuz

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// qbzFixture is a fake qbz-1 track: a FLAC header and encrypted segments,
// with the session infos and wrapped key that decrypt them.
type qbzFixture struct {
	infos    string   // session/start "infos"
	key      string   // file/url "key"
	init     []byte   // segment 0
	segments [][]byte // segments 1..n
	want     []byte   // the FLAC bytes the reader must yield
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustCipher(t *testing.T, key []byte) cipher.Block {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return block
}

// box builds an ISO BMFF box.
func box(typ string, payload ...[]byte) []byte {
	body := bytes.Join(payload, nil)
	out := binary.BigEndian.AppendUint32(nil, uint32(8+len(body)))
	return append(append(out, typ...), body...)
}

func uuidBox(t *testing.T, id string, payload []byte) []byte {
	t.Helper()
	raw, err := hex.DecodeString(id)
	if err != nil {
		t.Fatal(err)
	}
	return box("uuid", raw, payload)
}

// newQBZFixture encrypts frames, one segment per inner slice. Every second
// frame is left clear (flags 0), as Qobuz does for some frames.
func newQBZFixture(t *testing.T, frames [][][]byte) qbzFixture {
	t.Helper()
	salt, info := []byte("0123456789abcdef"), []byte("qbz-1 test info")
	seed, _ := hex.DecodeString(cmafSeed)
	sessionKey := make([]byte, 16)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, salt, info), sessionKey); err != nil {
		t.Fatal(err)
	}

	contentKey := []byte("content-key-0001")
	padded := append(append([]byte(nil), contentKey...), bytes.Repeat([]byte{16}, 16)...)
	wrapIV := []byte("wrap-iv-01234567")
	wrapped := make([]byte, len(padded))
	cipher.NewCBCEncrypter(mustCipher(t, sessionKey), wrapIV).CryptBlocks(wrapped, padded)

	// STREAMINFO without the last-metadata flag; the reader sets it.
	header := append([]byte("fLaC\x00\x00\x00\x22"), bytes.Repeat([]byte{0xAB}, 34)...)
	raw := append([]byte("junk"), header...)
	initPayload := binary.BigEndian.AppendUint16(make([]byte, 26), uint16(len(raw)))
	initPayload = append(initPayload, raw...)

	f := qbzFixture{
		infos: b64(salt) + "." + b64(info),
		key:   "qbz-1." + b64(wrapped) + "." + b64(wrapIV),
		init:  append(box("ftyp", []byte("iso6")), uuidBox(t, initUUID, initPayload)...),
	}
	f.want = append([]byte(nil), header...)
	f.want[4] |= 0x80

	const ivSize = 8
	for _, seg := range frames {
		table := []byte{0, 0, 0, 0}                     // version/flags, unused
		table = binary.BigEndian.AppendUint32(table, 0) // data offset, set below
		table = append(table, ivSize, 0, 0, byte(len(seg)))
		var mdat []byte
		for i, frame := range seg {
			iv := []byte(fmt.Sprintf("iv%06d", i))
			flags := uint16(1)
			enc := append([]byte(nil), frame...)
			if i%2 == 1 {
				flags = 0
			} else {
				counter := append(append([]byte(nil), iv...), make([]byte, 8)...)
				cipher.NewCTR(mustCipher(t, contentKey), counter).XORKeyStream(enc, enc)
			}
			table = binary.BigEndian.AppendUint32(table, uint32(len(frame)))
			table = append(table, 0, 0)
			table = binary.BigEndian.AppendUint16(table, flags)
			table = append(table, iv...)
			mdat = append(mdat, enc...)
			f.want = append(f.want, frame...)
		}
		u := uuidBox(t, segmentUUID, table)
		binary.BigEndian.PutUint32(u[24+4:], uint32(len(u)+8)) // audio starts after the mdat header
		f.segments = append(f.segments, append(u, box("mdat", mdat)...))
	}
	return f
}

// qbzServer serves session/start, file/url and the CDN segments of f. It
// checks the qbz-1 signatures and the session header. fileURL, if set,
// replaces the file/url answer.
func qbzServer(t *testing.T, f qbzFixture, fileURL func(w http.ResponseWriter, r *http.Request) bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkSig := func(endpoint string, q url.Values) {
			params := url.Values{}
			for k, v := range q {
				if k != "request_ts" && k != "request_sig" {
					params[k] = v
				}
			}
			if got, want := q.Get("request_sig"), cmafSignature(endpoint, params, q.Get("request_ts")); got != want {
				t.Errorf("%s request_sig = %q, want %q", endpoint, got, want)
			}
			if r.Header.Get("X-User-Auth-Token") != "token" || r.Header.Get("X-App-Id") != "app" {
				t.Errorf("%s auth headers = %v", endpoint, r.Header)
			}
		}
		switch {
		case r.URL.Path == "/session/start":
			if r.Method != http.MethodPost {
				t.Errorf("session/start method = %s, want POST", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.PostForm.Get("profile") != "qbz-1" {
				t.Errorf("session/start profile = %q", r.PostForm.Get("profile"))
			}
			checkSig("session/start", r.PostForm)
			fmt.Fprintf(w, `{"session_id":"sid-1","infos":%q}`, f.infos)
		case r.URL.Path == "/file/url":
			if r.Header.Get("X-Session-Id") != "sid-1" {
				t.Errorf("file/url X-Session-Id = %q, want sid-1", r.Header.Get("X-Session-Id"))
			}
			checkSig("file/url", r.URL.Query())
			if fileURL != nil && fileURL(w, r) {
				return
			}
			fmt.Fprintf(w, `{"url_template":%q,"key":%q,"n_segments":%d,"format_id":%s}`,
				srv.URL+"/seg/$SEGMENT$", f.key, len(f.segments), r.URL.Query().Get("format_id"))
		case strings.HasPrefix(r.URL.Path, "/seg/"):
			var n int
			if _, err := fmt.Sscanf(r.URL.Path, "/seg/%d", &n); err != nil || n > len(f.segments) {
				http.NotFound(w, r)
				return
			}
			if n == 0 {
				_, _ = w.Write(f.init)
				return
			}
			_, _ = w.Write(f.segments[n-1])
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	return srv
}

func TestCMAFSignature(t *testing.T) {
	params := url.Values{"track_id": {"5966783"}, "format_id": {"6"}, "intent": {"stream"}}
	// Params in name order, then the timestamp and the seed.
	want := md5hex("fileurlformat_id6intentstreamtrack_id59667831700000000" + cmafSeed)
	if got := cmafSignature("file/url", params, "1700000000"); got != want {
		t.Errorf("cmafSignature = %q, want %q", got, want)
	}
}

func TestCMAFStream(t *testing.T) {
	f := newQBZFixture(t, [][][]byte{
		{[]byte("frame-one-bytes"), []byte("frame-two"), []byte("frame-three-longer-than-a-block")},
		{[]byte("second-segment")},
	})
	srv := qbzServer(t, f, nil)
	defer srv.Close()

	rc, err := testClient(srv).cmafStream(t.Context(), "5966783", 27)
	if err != nil {
		t.Fatalf("cmafStream() error = %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if !bytes.Equal(got, f.want) {
		t.Errorf("stream bytes = %q, want %q", got, f.want)
	}
}

func TestDecryptSegmentRejectsBadInput(t *testing.T) {
	var key [16]byte
	f := newQBZFixture(t, [][][]byte{{[]byte("frame")}})
	seg := f.segments[0]
	noMdat := seg[:binary.BigEndian.Uint32(seg)] // the crypto box alone
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"no crypto box", box("mdat", []byte("x"))},
		{"no mdat", noMdat},
		{"truncated", seg[:len(seg)-2]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decryptSegment(tt.data, key); err == nil {
				t.Error("decryptSegment() error = nil, want an error")
			}
		})
	}
}

func TestUnwrapContentKeyRejectsBadTokens(t *testing.T) {
	var session [16]byte
	for _, token := range []string{"", "qbz-1.only", "qbz-1.AAAA.short", "qbz-1." + b64(make([]byte, 15)) + "." + b64(make([]byte, 16))} {
		if _, err := unwrapContentKey(session, token); err == nil {
			t.Errorf("unwrapContentKey(%q) error = nil, want an error", token)
		}
	}
}
