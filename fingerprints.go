package quic

import (
	"time"

	"github.com/malivvan/tls"
)

// This file contains preset FingerprintConfigs that mimic the QUIC transport parameter
// fingerprints of well-known browsers, combined with the corresponding uTLS ClientHello
// presets from github.com/malivvan/tls.
//
// The transport parameter values and orders are approximations based on publicly captured
// traffic of the respective browser versions. Browser fingerprints change between versions,
// so for production use you should capture the exact fingerprint of the browser you want to
// mimic and encode it in your own FingerprintConfig (or use a uTLS ClientHelloID together
// with TransportParameterOrder and ExtraTransportParameters).

// FingerprintChrome133 returns a FingerprintConfig mimicking Chrome 133.
// Chrome's ClientHello is mimicked via the uTLS HelloChrome_133 preset.
func FingerprintChrome133() *FingerprintConfig {
	return &FingerprintConfig{
		ClientHelloID: tls.HelloChrome_133,
		// Chrome marshals its transport parameters in this order
		// (with the values Chrome 133 advertises).
		TransportParameterOrder: []uint64{
			0x4,    // initial_max_data
			0x5,    // initial_max_stream_data_bidi_local
			0x6,    // initial_max_stream_data_bidi_remote
			0x7,    // initial_max_stream_data_uni
			0x9,    // initial_max_streams_uni
			0x8,    // initial_max_streams_bidi
			0x1,    // max_idle_timeout
			0x3,    // max_udp_payload_size
			0xe,    // active_connection_id_limit
			0xf,    // initial_source_connection_id
			0x2ab2, // grease_quic_bit
			0xb,    // max_ack_delay
			0xa,    // ack_delay_exponent
		},
		ExtraTransportParameters:       map[uint64][]byte{},
		GreaseQuicBit:                  true,
		InitialPacketSize:              1350,
		ConnectionIDLength:             8,
		MaxIdleTimeout:                 durationPtr(30 * time.Second),
		MaxUDPPayloadSize:              uint16Ptr(1350),
		MaxAckDelay:                    durationPtr(25 * time.Millisecond),
		AckDelayExponent:               uint8Ptr(3),
		ActiveConnectionIDLimit:        uint64Ptr(8),
		InitialMaxData:                 uint64Ptr(12517377),
		InitialMaxStreamDataBidiLocal:  uint64Ptr(6291456),
		InitialMaxStreamDataBidiRemote: uint64Ptr(262144),
		InitialMaxStreamDataUni:        uint64Ptr(262144),
		MaxBidiStreamNum:               uint64Ptr(100),
		MaxUniStreamNum:                uint64Ptr(3),
	}
}

// FingerprintEdge133 returns a FingerprintConfig mimicking Microsoft Edge 133.
// Edge is Chromium-based, so its QUIC fingerprint is identical to Chrome's.
func FingerprintEdge133() *FingerprintConfig {
	return FingerprintChrome133()
}

// FingerprintFirefox120 returns a FingerprintConfig mimicking Firefox 120.
// Firefox's ClientHello is mimicked via the uTLS HelloFirefox_120 preset.
func FingerprintFirefox120() *FingerprintConfig {
	return &FingerprintConfig{
		ClientHelloID: tls.HelloFirefox_120,
		// Firefox marshals its transport parameters in this order.
		TransportParameterOrder: []uint64{
			0x4,    // initial_max_data
			0x5,    // initial_max_stream_data_bidi_local
			0x6,    // initial_max_stream_data_bidi_remote
			0x7,    // initial_max_stream_data_uni
			0x8,    // initial_max_streams_bidi
			0x9,    // initial_max_streams_uni
			0x3,    // max_udp_payload_size
			0xf,    // initial_source_connection_id
			0x2ab2, // grease_quic_bit
		},
		ExtraTransportParameters:       map[uint64][]byte{},
		GreaseQuicBit:                  true,
		InitialPacketSize:              1350,
		ConnectionIDLength:             8,
		MaxUDPPayloadSize:              uint16Ptr(1350),
		InitialMaxData:                 uint64Ptr(131072),
		InitialMaxStreamDataBidiLocal:  uint64Ptr(65536),
		InitialMaxStreamDataBidiRemote: uint64Ptr(65536),
		InitialMaxStreamDataUni:        uint64Ptr(65536),
		MaxBidiStreamNum:               uint64Ptr(16),
		MaxUniStreamNum:                uint64Ptr(16),
	}
}

// FingerprintSafari160 returns a FingerprintConfig mimicking Safari 16.0.
// Safari's ClientHello is mimicked via the uTLS HelloSafari_16_0 preset.
func FingerprintSafari160() *FingerprintConfig {
	return &FingerprintConfig{
		ClientHelloID: tls.HelloSafari_16_0,
		TransportParameterOrder: []uint64{
			0x4, // initial_max_data
			0x5, // initial_max_stream_data_bidi_local
			0x6, // initial_max_stream_data_bidi_remote
			0x7, // initial_max_stream_data_uni
			0x9, // initial_max_streams_uni
			0x8, // initial_max_streams_bidi
			0x1, // max_idle_timeout
			0x3, // max_udp_payload_size
			0xe, // active_connection_id_limit
			0xf, // initial_source_connection_id
		},
		ExtraTransportParameters:       map[uint64][]byte{},
		InitialPacketSize:              1350,
		ConnectionIDLength:             8,
		MaxIdleTimeout:                 durationPtr(30 * time.Second),
		MaxUDPPayloadSize:              uint16Ptr(1350),
		ActiveConnectionIDLimit:        uint64Ptr(2),
		InitialMaxData:                 uint64Ptr(1048576),
		InitialMaxStreamDataBidiLocal:  uint64Ptr(262144),
		InitialMaxStreamDataBidiRemote: uint64Ptr(262144),
		InitialMaxStreamDataUni:        uint64Ptr(262144),
		MaxBidiStreamNum:               uint64Ptr(100),
		MaxUniStreamNum:                uint64Ptr(3),
	}
}

func durationPtr(d time.Duration) *time.Duration { return &d }
func uint16Ptr(u uint16) *uint16                 { return &u }
func uint64Ptr(u uint64) *uint64                 { return &u }
func uint8Ptr(u uint8) *uint8                    { return &u }
