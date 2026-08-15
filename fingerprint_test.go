package quic

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/malivvan/quic/internal/protocol"
	"github.com/malivvan/quic/internal/testdata"
	"github.com/malivvan/quic/internal/wire"
	"github.com/malivvan/quic/quicvarint"
)

func TestParseClientHelloFingerprint(t *testing.T) {
	// Build a minimal ClientHello message.
	ch := []byte{0x01, 0, 0, 0} // handshake type + 24-bit length (fixed up below)
	body := []byte{0x03, 0x03}  // legacy version
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)          // session ID length
	body = append(body, 0, 4)       // cipher suites length
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0x13, 0x03) // TLS_CHACHA20_POLY1305_SHA256
	body = append(body, 1, 0)       // compression methods
	exts := []byte{}
	// server_name: "example.com" (11 bytes)
	exts = append(exts, 0, 0, 0, 16, 0, 14, 0, 0, 11)
	exts = append(exts, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d)
	// ALPN: h3
	exts = append(exts, 0, 0x10, 0, 5, 0, 3, 2, 0x68, 0x33)
	// supported_versions: GREASE + TLS 1.3 + GREASE
	exts = append(exts, 0, 0x2b, 0, 7, 6, 0x2a, 0x2a, 0x03, 0x04, 0x8a, 0x8a)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	ch[1] = byte(len(body) >> 16)
	ch[2] = byte(len(body) >> 8)
	ch[3] = byte(len(body))
	ch = append(ch, body...)

	cipherSuites, supportedVersions, extensions, snis, alpn := parseClientHelloFingerprint(ch)
	require.Equal(t, []uint16{0x1301, 0x1303}, cipherSuites)
	require.Equal(t, []uint16{0x2a2a, 0x0304, 0x8a8a}, supportedVersions)
	require.Equal(t, []uint16{0x0000, 0x0010, 0x002b}, extensions)
	require.Equal(t, []string{"example.com"}, snis)
	require.Equal(t, []string{"h3"}, alpn)
}

func TestFingerprintFromConnectionState(t *testing.T) {
	// Raw transport parameters: 0x4 = initial_max_data (value 12345), 0x2ab2 = grease_quic_bit (empty), 0xdead = unknown.
	var rawTPs []byte
	rawTPs = quicvarint.Append(rawTPs, 0x4)
	rawTPs = quicvarint.Append(rawTPs, 2)
	rawTPs = append(rawTPs, 0x30, 0x39)
	rawTPs = quicvarint.Append(rawTPs, 0x2ab2)
	rawTPs = quicvarint.Append(rawTPs, 0)
	rawTPs = quicvarint.Append(rawTPs, 0xdead)
	rawTPs = quicvarint.Append(rawTPs, 3)
	rawTPs = append(rawTPs, 1, 2, 3)
	cs := ConnectionState{
		Version:                    Version1,
		ClientHello:                []byte{0x01, 0, 0, 0},
		SrcConnectionID:            protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		DestConnectionID:           protocol.ParseConnectionID([]byte{9, 10, 11, 12}),
		InitialPacketSize:          1350,
		PeerTransportParametersRaw: rawTPs,
	}
	fp := cs.Fingerprint()
	require.Equal(t, Version1, fp.Version)
	require.Equal(t, protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}), fp.SrcConnectionID)
	require.Equal(t, 1350, fp.InitialPacketSize)
	require.Equal(t, []uint64{0x4, 0x2ab2, 0xdead}, fp.TransportParameterIDs)
	require.Equal(t, []byte{0x30, 0x39}, fp.TransportParameters[0x4])
	require.Empty(t, fp.TransportParameters[0x2ab2])
	require.Equal(t, []byte{1, 2, 3}, fp.TransportParameters[0xdead])
}

func TestMarshalWithConfigOrder(t *testing.T) {
	params := &wire.TransportParameters{
		InitialMaxData:                100,
		InitialMaxStreamDataBidiLocal: 200,
		MaxIdleTimeout:                30 * time.Second,
		ActiveConnectionIDLimit:       8,
		InitialSourceConnectionID:     protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		GreaseQuicBit:                 true,
	}

	// Default marshal: starts with a random GREASE parameter.
	def := params.Marshal(protocol.PerspectiveClient)
	require.NotEmpty(t, def)

	// Ordered marshal: only the listed parameters, in the given order, then the rest.
	ordered := params.MarshalWithConfig(protocol.PerspectiveClient, []uint64{0xf, 0x2ab2, 0x1}, nil)
	// initial_source_connection_id (0xf), grease_quic_bit (0x2ab2), max_idle_timeout (0x1), then the rest.
	got := readParameterIDs(t, ordered)
	require.Equal(t, []uint64{0xf, 0x2ab2, 0x1}, got[:3])
	// initial_max_data (0x4) must follow after the listed ones (it is not listed, so it comes in default order).
	require.Contains(t, got[3:], uint64(0x4))
	// No random GREASE (27 + 31*k) in ordered mode.
	for _, id := range got {
		require.False(t, id >= 27 && (id-27)%31 == 0)
	}

	// Extra parameters are appended at the end.
	withExtra := params.MarshalWithConfig(protocol.PerspectiveClient, nil, map[uint64][]byte{0x1234: {0xaa}})
	require.NotEmpty(t, withExtra)
	require.True(t, bytes.Contains(withExtra, []byte{0xaa}))
}

func TestFingerprintConfigApplyToParams(t *testing.T) {
	fp := FingerprintChrome133()
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiLocal: 10,
		InitialMaxData:                20,
		MaxAckDelay:                   protocol.MaxAckDelayInclGranularity,
		MaxUDPPayloadSize:             protocol.MaxPacketBufferSize,
		AckDelayExponent:              protocol.AckDelayExponent,
		MaxDatagramFrameSize:          protocol.InvalidByteCount,
	}
	fp.applyToParams(params)
	require.True(t, params.GreaseQuicBit)
	require.Equal(t, uint64(12517377), uint64(params.InitialMaxData))
	require.Equal(t, uint64(6291456), uint64(params.InitialMaxStreamDataBidiLocal))
	require.Equal(t, uint8(3), params.AckDelayExponent)
	require.Equal(t, uint64(1350), uint64(params.MaxUDPPayloadSize))
	require.Equal(t, uint64(8), params.ActiveConnectionIDLimit)
	require.Equal(t, 25*time.Millisecond, params.MaxAckDelay)

	// The preset's TP order must marshal the parameters in exactly that order.
	ordered := params.MarshalWithConfig(protocol.PerspectiveClient, fp.TransportParameterOrder, fp.ExtraTransportParameters)
	got := readParameterIDs(t, ordered)
	require.Equal(t, fp.TransportParameterOrder, got)
}

// readParameterIDs reads the transport parameter IDs from marshaled transport parameters.
func readParameterIDs(t *testing.T, b []byte) []uint64 {
	t.Helper()
	var ids []uint64
	for len(b) > 0 {
		id, l, err := parseVarint(b)
		require.NoError(t, err)
		ids = append(ids, id)
		b = b[l:]
		valLen, l, err := parseVarint(b)
		require.NoError(t, err)
		b = b[l:]
		require.LessOrEqual(t, valLen, uint64(len(b)))
		b = b[valLen:]
	}
	return ids
}

func parseVarint(b []byte) (uint64, int, error) {
	return quicvarint.Parse(b)
}

func TestFingerprintClientServer(t *testing.T) {
	// End-to-end test: a client mimicking Chrome connects to a server.
	// The server must be able to fingerprint the connection.
	clientTLSConf := testdata.GetTLSConfig()
	clientTLSConf.ServerName = "localhost"
	clientTLSConf.RootCAs = testdata.GetRootCA()
	clientTLSConf.NextProtos = []string{"crypto-setup"}
	serverTLSConf := testdata.GetTLSConfig()
	serverTLSConf.NextProtos = []string{"crypto-setup"}

	clientInfoChan := make(chan *ClientInfo, 1)
	server, err := ListenAddr(
		"127.0.0.1:0",
		serverTLSConf,
		&Config{
			GetConfigForClient: func(info *ClientInfo) (*Config, error) {
				select {
				case clientInfoChan <- info:
				default:
				}
				return nil, nil
			},
		},
	)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := DialAddr(
		ctx,
		server.Addr().String(),
		clientTLSConf,
		&Config{
			Fingerprint:   FingerprintChrome133(),
			GreaseQuicBit: true,
		},
	)
	require.NoError(t, err)
	defer client.CloseWithError(0, "")

	// The server must be able to accept the connection.
	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)

	// Exchange data on a stream. With grease_quic_bit negotiated on both sides,
	// ~50% of the 1-RTT packets carry a cleared QUIC bit (RFC 9287), which both
	// endpoints must tolerate.
	clientStream, err := client.OpenStreamSync(ctx)
	require.NoError(t, err)
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	_, err = clientStream.Write(payload)
	require.NoError(t, err)
	require.NoError(t, clientStream.Close())
	serverStream, err := serverConn.AcceptStream(ctx)
	require.NoError(t, err)
	received := make([]byte, len(payload))
	_, err = io.ReadFull(serverStream, received)
	require.NoError(t, err)
	require.Equal(t, payload, received)

	// The GetConfigForClient callback must have been called with fingerprint data.
	select {
	case info := <-clientInfoChan:
		require.Equal(t, Version1, info.Version)
		require.Greater(t, info.InitialPacketSize, 0)
		require.Equal(t, 8, info.SrcConnectionID.Len()) // Chrome uses 8-byte source connection IDs
		require.Greater(t, info.DestConnectionID.Len(), 0)
		require.NotEmpty(t, info.ClientHello)
		require.Equal(t, byte(0x01), info.ClientHello[0]) // ClientHello handshake type
	default:
		t.Fatal("GetConfigForClient was not called")
	}

	// Server-side connection state must contain the full fingerprint data.
	state := serverConn.ConnectionState()
	require.NotEmpty(t, state.ClientHello)
	require.NotEmpty(t, state.PeerTransportParametersRaw)
	require.NotNil(t, state.PeerTransportParameters)
	require.True(t, state.PeerTransportParameters.GreaseQuicBit)
	require.Equal(t, Version1, state.Version)
	require.Equal(t, 8, state.SrcConnectionID.Len())
	require.True(t, state.GreaseQuicBit)

	fp := state.Fingerprint()
	require.Equal(t, Version1, fp.Version)
	require.NotEmpty(t, fp.CipherSuites)
	require.NotEmpty(t, fp.Extensions)
	require.Contains(t, fp.TransportParameterIDs, uint64(0x2ab2))
	require.NotEmpty(t, fp.TransportParameters)

	// The client's transport parameters must have been marshaled in the order
	// prescribed by the Chrome fingerprint preset (FingerprintChrome133).
	chromeOrder := FingerprintChrome133().TransportParameterOrder
	require.Equal(t, chromeOrder, fp.TransportParameterIDs)

	// Client-side state must expose the server's transport parameters as well.
	clientState := client.ConnectionState()
	require.NotNil(t, clientState.PeerTransportParameters)
	require.NotEmpty(t, clientState.PeerTransportParametersRaw)
	require.Equal(t, 8, clientState.SrcConnectionID.Len())
}
