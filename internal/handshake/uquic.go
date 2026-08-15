package handshake

import (
	"fmt"

	"github.com/malivvan/tls"

	"github.com/malivvan/quic/quicvarint"
)

// newUQUICClientConn creates a uTLS QUIC client connection that mimics the TLS ClientHello
// of the client identified by clientHelloID (e.g. tls.HelloChrome_133).
//
// The quic-go transport parameters (tpBytes) are injected into the ClientHello's
// quic_transport_parameters extension. This is necessary because the uTLS presets shipped
// with github.com/malivvan/tls do not include that extension, and the uTLS QUIC path does
// not substitute the transport parameters set via SetTransportParameters into the ClientHello.
//
// Additionally, the preset is adapted for QUIC:
//   - the ALPN and ALPS extensions are replaced with the protocols configured for this connection
//     (the presets are captured from TCP connections and contain TCP-style protocols like h2),
//   - the supported_versions extension is restricted to TLS 1.3 (plus a GREASE value),
//     as required by RFC 9001 Section 8.2.
//
// Note that UQUICConn.ApplyPreset does not mark the preset as applied, so buildHandshakeState
// would re-apply the unmodified preset at Start. To prevent this, the connection is created
// with the HelloCustom ClientHelloID, which makes applyPresetByID a no-op.
func newUQUICClientConn(config *tls.QUICConfig, clientHelloID tls.ClientHelloID, tpBytes []byte) *tls.UQUICConn {
	qconn := tls.UQUICClient(config, tls.HelloCustom)

	spec, err := tls.UTLSIdToSpec(clientHelloID)
	if err != nil {
		// The handshake will fail with a clear TLS error once Start is called.
		// There's nothing sensible we could do here.
		return qconn
	}

	// Build the transport parameters extension from the raw bytes.
	// Using FakeQUICTransportParameter for every parameter preserves the exact order,
	// values and GREASE parameters of the marshaled transport parameters.
	tps := make(tls.TransportParameters, 0, 16)
	b := tpBytes
	for len(b) > 0 {
		id, l, err := quicvarint.Parse(b)
		if err != nil {
			break
		}
		b = b[l:]
		valLen, l, err := quicvarint.Parse(b)
		if err != nil {
			break
		}
		b = b[l:]
		if uint64(len(b)) < valLen {
			break
		}
		tps = append(tps, &tls.FakeQUICTransportParameter{Id: id, Val: b[:valLen]})
		b = b[valLen:]
	}

	// Replace an existing QUIC transport parameters extension, if the spec has one.
	tpExt := &tls.QUICTransportParametersExtension{TransportParameters: tps}
	inserted := false
	exts := make([]tls.TLSExtension, 0, len(spec.Extensions)+1)
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*tls.QUICTransportParametersExtension); ok {
			exts = append(exts, tpExt)
			inserted = true
			continue
		}
		if !inserted {
			// Insert the extension right before the key share extension, which is where
			// real browsers (Chrome, Firefox, Safari) place quic_transport_parameters.
			if _, ok := ext.(*tls.KeyShareExtension); ok {
				exts = append(exts, tpExt)
				inserted = true
			}
		}
		exts = append(exts, ext)
	}
	if !inserted {
		exts = append(exts, tpExt)
	}
	spec.Extensions = exts

	// Replace the ALPN and ALPS extensions with the protocols configured for this connection.
	// The uTLS presets are captured from TCP connections and contain TCP-style protocols
	// (e.g. "h2", "http/1.1"), which are not valid for QUIC (RFC 9001 Section 8.1).
	// If no protocols are configured, the extensions are removed entirely.
	alpn := config.TLSConfig.NextProtos
	if len(alpn) == 0 {
		filtered := exts[:0]
		for _, ext := range exts {
			switch ext.(type) {
			case *tls.ALPNExtension, *tls.ApplicationSettingsExtension, *tls.ApplicationSettingsExtensionNew:
				continue
			}
			filtered = append(filtered, ext)
		}
		exts = filtered
	} else {
		for _, ext := range exts {
			switch e := ext.(type) {
			case *tls.ALPNExtension:
				e.AlpnProtocols = alpn
			case *tls.ApplicationSettingsExtension:
				e.SupportedProtocols = alpn
			case *tls.ApplicationSettingsExtensionNew:
				e.SupportedProtocols = alpn
			}
		}
	}
	spec.Extensions = exts

	// Restrict supported_versions to TLS 1.3 (+ GREASE), as required for QUIC.
	for _, ext := range spec.Extensions {
		if sv, ok := ext.(*tls.SupportedVersionsExtension); ok {
			sv.Versions = []uint16{tls.GREASE_PLACEHOLDER, tls.VersionTLS13}
		}
	}

	if err := qconn.ApplyPreset(&spec); err != nil {
		// This can only fail for structural reasons (e.g. an invalid spec).
		panic(fmt.Sprintf("quic: applying uTLS ClientHello preset failed: %s", err))
	}

	// ApplyPreset derives the TLS versions from the spec and overwrites the config's
	// MinVersion/MaxVersion. QUIC requires exactly TLS 1.3, and UQUICConn.Start enforces
	// MinVersion >= TLS 1.3, so restore the versions here.
	config.TLSConfig.MinVersion = tls.VersionTLS13
	config.TLSConfig.MaxVersion = tls.VersionTLS13

	return qconn
}
