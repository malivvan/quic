package quic

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractClientHelloFromFrames(t *testing.T) {
	// A CRYPTO frame (type 0x06), followed by PADDING and another CRYPTO frame with contiguous offset.
	payload := []byte{0x06, 0x00, 0x04, 't', 'e', 's', 't'}
	payload = append(payload, 0x00, 0x00, 0x00) // padding
	payload = append(payload, 0x06, 0x04, 0x03, 'f', 'o', 'o')
	require.Equal(t, []byte("testfoo"), extractClientHelloFromFrames(payload))

	// A non-CRYPTO frame stops the extraction.
	payload = []byte{0x01} // PING
	require.Empty(t, extractClientHelloFromFrames(payload))

	// A CRYPTO frame with a non-contiguous offset is not concatenated.
	payload = []byte{0x06, 0x04, 0x03, 'f', 'o', 'o'} // offset 4, but nothing before it
	require.Empty(t, extractClientHelloFromFrames(payload))

	// Malformed frames are ignored.
	payload = []byte{0x06, 0xff}
	require.Empty(t, extractClientHelloFromFrames(payload))
}
