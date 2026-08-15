package quic

import (
	"encoding/binary"
	"time"

	"github.com/malivvan/tls"

	"github.com/malivvan/quic/internal/protocol"
	"github.com/malivvan/quic/internal/wire"
)

// Fingerprint is a normalized summary of the information a connection reveals about the peer.
// It is intended to identify the peer's Quic implementation, and can be used as a hashable
// input for fingerprinting rules (e.g. allow/deny lists or rate limiting).
//
// All fields are derived from public information exchanged during the connection establishment.
type Fingerprint struct {
	// Version is the Quic version of the connection.
	Version Version
	// ClientHello contains the raw ClientHello bytes (server-side only).
	ClientHello []byte
	// TransportParameterIDs lists the IDs of the peer's transport parameters, in wire order.
	// This includes GREASE and unknown parameters.
	TransportParameterIDs []uint64
	// TransportParameters maps the peer's transport parameter IDs to their raw values,
	// exactly as received on the wire.
	TransportParameters map[uint64][]byte
	// CipherSuites lists the cipher suites offered in the ClientHello, in order.
	CipherSuites []uint16
	// SupportedVersions lists the TLS versions offered in the ClientHello's supported_versions
	// extension (including GREASE values), in order.
	SupportedVersions []uint16
	// Extensions lists the TLS extension types of the ClientHello, in order.
	Extensions []uint16
	// SNIs lists the server names sent in the ClientHello's server_name extension.
	SNIs []string
	// ALPN lists the protocols offered in the ClientHello's ALPN extension, in order.
	ALPN []string
	// SrcConnectionID is the source connection ID of the client's first Initial packet.
	SrcConnectionID ConnectionID
	// DestConnectionID is the destination connection ID of the client's first Initial packet.
	DestConnectionID ConnectionID
	// InitialPacketSize is the size of the client's first Initial packet.
	InitialPacketSize int
	// GreaseQuicBit indicates whether the peer advertised the grease_quic_bit transport
	// parameter (RFC 9287).
	GreaseQuicBit bool
}

const (
	tlsExtServerName         = 0x0000
	tlsExtALPN               = 0x0010
	tlsExtSupportedVersions  = 0x002b
	handshakeTypeClientHello = 0x01
)

// parseClientHelloFingerprint extracts the fingerprint-relevant fields from a raw ClientHello
// message (as captured on the wire, i.e. starting with the handshake type byte).
// All parsing errors are ignored; malformed ClientHellos yield empty results.
func parseClientHelloFingerprint(ch []byte) (cipherSuites, supportedVersions, extensions []uint16, snis, alpn []string) {
	if len(ch) < 4 || ch[0] != handshakeTypeClientHello {
		return nil, nil, nil, nil, nil
	}
	msgLen := int(ch[1])<<16 | int(ch[2])<<8 | int(ch[3])
	if len(ch) < 4+msgLen {
		msgLen = len(ch) - 4
	}
	b := ch[4 : 4+msgLen]
	// legacy_version (2) + random (32)
	if len(b) < 34 {
		return nil, nil, nil, nil, nil
	}
	b = b[34:]
	// session_id
	if len(b) < 1 {
		return nil, nil, nil, nil, nil
	}
	sidLen := int(b[0])
	b = b[1:]
	if len(b) < sidLen {
		return nil, nil, nil, nil, nil
	}
	b = b[sidLen:]
	// cipher_suites
	if len(b) < 2 {
		return nil, nil, nil, nil, nil
	}
	csLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < csLen {
		return nil, nil, nil, nil, nil
	}
	for i := 0; i+1 < csLen; i += 2 {
		cipherSuites = append(cipherSuites, binary.BigEndian.Uint16(b[i:]))
	}
	b = b[csLen:]
	// compression_methods
	if len(b) < 1 {
		return nil, nil, nil, nil, nil
	}
	cmLen := int(b[0])
	b = b[1:]
	if len(b) < cmLen {
		return nil, nil, nil, nil, nil
	}
	b = b[cmLen:]
	// extensions
	if len(b) < 2 {
		return cipherSuites, nil, nil, nil, nil
	}
	extsLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < extsLen {
		extsLen = len(b)
	}
	exts := b[:extsLen]
	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts)
		extLen := int(binary.BigEndian.Uint16(exts[2:]))
		exts = exts[4:]
		extensions = append(extensions, extType)
		if extLen > len(exts) {
			break
		}
		data := exts[:extLen]
		switch extType {
		case tlsExtServerName:
			// server_name_list (2) + name_type (1) + name_len (2) + name
			if len(data) >= 5 {
				nameLen := int(binary.BigEndian.Uint16(data[3:]))
				if len(data) >= 5+nameLen {
					snis = append(snis, string(data[5:5+nameLen]))
				}
			}
		case tlsExtALPN:
			// protocol_name_list (2) + (len (1) + protocol)*
			if len(data) >= 2 {
				list := data[2:]
				for len(list) >= 2 {
					l := int(list[0])
					list = list[1:]
					if l > len(list) {
						break
					}
					alpn = append(alpn, string(list[:l]))
					list = list[l:]
				}
			}
		case tlsExtSupportedVersions:
			// list length (1) + (2 bytes per version)*
			if len(data) >= 1 {
				l := int(data[0])
				versions := data[1:]
				if l > len(versions) {
					l = len(versions)
				}
				for i := 0; i+1 < l; i += 2 {
					supportedVersions = append(supportedVersions, binary.BigEndian.Uint16(versions[i:]))
				}
			}
		}
		exts = exts[extLen:]
	}
	return cipherSuites, supportedVersions, extensions, snis, alpn
}

// FingerprintConfig configures how the client presents itself on the wire, in order to mimic
// the connection establishment behavior of a specific Quic implementation (e.g. a browser).
// It is client-side only; it is ignored by the server.
//
// A FingerprintConfig can be combined with the tls.Config's uTLS support
// (github.com/malivvan/tls.ClientHelloID) to also mimic the TLS-level ClientHello.
type FingerprintConfig struct {
	// ClientHelloID selects the uTLS ClientHello preset used to mimic the TLS fingerprint
	// of a specific client (e.g. tls.HelloChrome_133). The zero value disables TLS fingerprint
	// mimicry and uses the Go TLS stack's default ClientHello.
	// Note: when set, TLS session resumption (and thus 0-RTT) is not supported.
	ClientHelloID tls.ClientHelloID

	// TransportParameterOrder sets the order in which the client's transport parameters are
	// marshaled. IDs not listed are appended in the default order after the listed ones.
	// nil means the quic-go default order (with a random GREASE parameter prepended).
	// When set, no random GREASE parameter is added; use ExtraTransportParameters to add
	// GREASE parameters with full control.
	TransportParameterOrder []uint64
	// ExtraTransportParameters adds transport parameters with the given raw values
	// (ID -> value bytes), e.g. GREASE parameters.
	ExtraTransportParameters map[uint64][]byte

	// InitialPacketSize overrides the size of the client's initial packets.
	// 0 means use Config.InitialPacketSize. Values below 1200 are invalid.
	InitialPacketSize uint16
	// ConnectionIDLength sets the length of the client's source connection ID.
	// 0 means use the Transport's default connection ID length.
	// NOTE: incoming short-header packets are routed based on Transport.ConnectionIDLength,
	// which must be set to the same value, otherwise packets from the server cannot be routed.
	ConnectionIDLength int

	// GreaseQuicBit sends the grease_quic_bit transport parameter (RFC 9287).
	// Once the peer also advertises grease_quic_bit, the client sets the QUIC bit
	// randomly on ~50% of the packets it sends.
	GreaseQuicBit bool

	// The following fields override individual transport parameter values.
	// nil means keep the default value derived from the Config.

	// MaxIdleTimeout overrides the advertised max_idle_timeout.
	MaxIdleTimeout *time.Duration
	// MaxUDPPayloadSize overrides the advertised max_udp_payload_size.
	MaxUDPPayloadSize *uint16
	// MaxAckDelay overrides the advertised max_ack_delay.
	MaxAckDelay *time.Duration
	// AckDelayExponent overrides the advertised ack_delay_exponent. When set, ACK frames are
	// encoded using this exponent.
	AckDelayExponent *uint8
	// ActiveConnectionIDLimit overrides the advertised active_connection_id_limit.
	ActiveConnectionIDLimit *uint64
	// InitialMaxData overrides the advertised initial_max_data.
	InitialMaxData *uint64
	// InitialMaxStreamDataBidiLocal overrides the advertised initial_max_stream_data_bidi_local.
	InitialMaxStreamDataBidiLocal *uint64
	// InitialMaxStreamDataBidiRemote overrides the advertised initial_max_stream_data_bidi_remote.
	InitialMaxStreamDataBidiRemote *uint64
	// InitialMaxStreamDataUni overrides the advertised initial_max_stream_data_uni.
	InitialMaxStreamDataUni *uint64
	// MaxBidiStreamNum overrides the advertised initial_max_streams_bidi.
	// WARNING: advertising more streams than Config.MaxIncomingStreams allows results in a
	// connection error if the peer opens more streams than allowed.
	MaxBidiStreamNum *uint64
	// MaxUniStreamNum overrides the advertised initial_max_streams_uni.
	// WARNING: advertising more streams than Config.MaxIncomingUniStreams allows results in a
	// connection error if the peer opens more streams than allowed.
	MaxUniStreamNum *uint64
	// DisableActiveMigration sends the disable_active_migration transport parameter.
	DisableActiveMigration bool
}

// applyToParams applies the fingerprint configuration to the transport parameters that will
// be sent by the client.
func (f *FingerprintConfig) applyToParams(params *wire.TransportParameters) {
	if f == nil {
		return
	}
	params.GreaseQuicBit = params.GreaseQuicBit || f.GreaseQuicBit
	if f.MaxIdleTimeout != nil {
		params.MaxIdleTimeout = *f.MaxIdleTimeout
	}
	if f.MaxUDPPayloadSize != nil {
		params.MaxUDPPayloadSize = protocol.ByteCount(*f.MaxUDPPayloadSize)
	}
	if f.MaxAckDelay != nil {
		params.MaxAckDelay = *f.MaxAckDelay
	}
	if f.AckDelayExponent != nil {
		params.AckDelayExponent = *f.AckDelayExponent
	}
	if f.ActiveConnectionIDLimit != nil {
		params.ActiveConnectionIDLimit = *f.ActiveConnectionIDLimit
	}
	if f.InitialMaxData != nil {
		params.InitialMaxData = protocol.ByteCount(*f.InitialMaxData)
	}
	if f.InitialMaxStreamDataBidiLocal != nil {
		params.InitialMaxStreamDataBidiLocal = protocol.ByteCount(*f.InitialMaxStreamDataBidiLocal)
	}
	if f.InitialMaxStreamDataBidiRemote != nil {
		params.InitialMaxStreamDataBidiRemote = protocol.ByteCount(*f.InitialMaxStreamDataBidiRemote)
	}
	if f.InitialMaxStreamDataUni != nil {
		params.InitialMaxStreamDataUni = protocol.ByteCount(*f.InitialMaxStreamDataUni)
	}
	if f.MaxBidiStreamNum != nil {
		params.MaxBidiStreamNum = protocol.StreamNum(*f.MaxBidiStreamNum)
	}
	if f.MaxUniStreamNum != nil {
		params.MaxUniStreamNum = protocol.StreamNum(*f.MaxUniStreamNum)
	}
	if f.DisableActiveMigration {
		params.DisableActiveMigration = true
	}
}

// ackDelayExponent returns the ack delay exponent to use for encoding ACK frames, or 0 if the
// default (protocol.AckDelayExponent) should be used.
func (f *FingerprintConfig) ackDelayExponent() uint8 {
	if f == nil || f.AckDelayExponent == nil {
		return 0
	}
	return *f.AckDelayExponent
}
