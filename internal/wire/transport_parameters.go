package wire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"time"

	"github.com/malivvan/quic/internal/protocol"
	"github.com/malivvan/quic/internal/qerr"
	"github.com/malivvan/quic/quicvarint"
)

// AdditionalTransportParametersClient are additional transport parameters that will be added
// to the client's transport parameters.
// This is not intended for production use, but _only_ to increase the size of the ClientHello beyond
// the usual size of less than 1 MTU.
var AdditionalTransportParametersClient map[uint64][]byte

const transportParameterMarshalingVersion = 1

type transportParameterID uint64

const (
	originalDestinationConnectionIDParameterID transportParameterID = 0x0
	maxIdleTimeoutParameterID                  transportParameterID = 0x1
	statelessResetTokenParameterID             transportParameterID = 0x2
	maxUDPPayloadSizeParameterID               transportParameterID = 0x3
	initialMaxDataParameterID                  transportParameterID = 0x4
	initialMaxStreamDataBidiLocalParameterID   transportParameterID = 0x5
	initialMaxStreamDataBidiRemoteParameterID  transportParameterID = 0x6
	initialMaxStreamDataUniParameterID         transportParameterID = 0x7
	initialMaxStreamsBidiParameterID           transportParameterID = 0x8
	initialMaxStreamsUniParameterID            transportParameterID = 0x9
	ackDelayExponentParameterID                transportParameterID = 0xa
	maxAckDelayParameterID                     transportParameterID = 0xb
	disableActiveMigrationParameterID          transportParameterID = 0xc
	preferredAddressParameterID                transportParameterID = 0xd
	activeConnectionIDLimitParameterID         transportParameterID = 0xe
	initialSourceConnectionIDParameterID       transportParameterID = 0xf
	retrySourceConnectionIDParameterID         transportParameterID = 0x10
	// RFC 9221
	maxDatagramFrameSizeParameterID transportParameterID = 0x20
	// https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/09/
	resetStreamAtParameterID transportParameterID = 0x1d
	// https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/07/
	// When removing support for this codepoint, increment transportParameterMarshalingVersion
	// to prevent 0-RTT resumption with tickets that remember it.
	legacyResetStreamAtParameterID transportParameterID = 0x17f7586d2cb571
	// https://datatracker.ietf.org/doc/draft-ietf-quic-ack-frequency/11/
	minAckDelayParameterID transportParameterID = 0xff04de1b
	// RFC 9287
	greaseQuicBitParameterID transportParameterID = 0x2ab2
)

// PreferredAddress is the value encoding in the preferred_address transport parameter
type PreferredAddress struct {
	IPv4, IPv6          netip.AddrPort
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

// TransportParameters are parameters sent to the peer during the handshake
type TransportParameters struct {
	InitialMaxStreamDataBidiLocal  protocol.ByteCount
	InitialMaxStreamDataBidiRemote protocol.ByteCount
	InitialMaxStreamDataUni        protocol.ByteCount
	InitialMaxData                 protocol.ByteCount

	MaxAckDelay      time.Duration
	AckDelayExponent uint8

	DisableActiveMigration bool

	MaxUDPPayloadSize protocol.ByteCount

	MaxUniStreamNum  protocol.StreamNum
	MaxBidiStreamNum protocol.StreamNum

	MaxIdleTimeout time.Duration

	PreferredAddress *PreferredAddress

	OriginalDestinationConnectionID protocol.ConnectionID
	InitialSourceConnectionID       protocol.ConnectionID
	RetrySourceConnectionID         *protocol.ConnectionID // use a pointer here to distinguish zero-length connection IDs from missing transport parameters

	StatelessResetToken     *protocol.StatelessResetToken
	ActiveConnectionIDLimit uint64

	MaxDatagramFrameSize protocol.ByteCount // RFC 9221
	EnableResetStreamAt  bool               // https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/09/
	MinAckDelay          *time.Duration

	// GreaseQuicBit indicates that the peer sent the grease_quic_bit transport parameter (RFC 9287).
	GreaseQuicBit bool
	// TransportParameterIDs contains the IDs of all transport parameters received, in the order they
	// appeared on the wire. This includes unknown and GREASE parameters, and is intended for fingerprinting.
	TransportParameterIDs []uint64
}

// Unmarshal the transport parameters
func (p *TransportParameters) Unmarshal(data []byte, sentBy protocol.Perspective) error {
	if err := p.unmarshal(data, sentBy, false); err != nil {
		return &qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: err.Error(),
		}
	}
	return nil
}

func (p *TransportParameters) unmarshal(b []byte, sentBy protocol.Perspective, fromSessionTicket bool) error {
	// needed to check that every parameter is only sent at most once
	parameterIDs := make([]transportParameterID, 0, 32)

	var (
		readOriginalDestinationConnectionID bool
		readInitialSourceConnectionID       bool
	)

	p.AckDelayExponent = protocol.DefaultAckDelayExponent
	p.MaxAckDelay = protocol.DefaultMaxAckDelay
	p.MaxDatagramFrameSize = protocol.InvalidByteCount
	p.ActiveConnectionIDLimit = protocol.DefaultActiveConnectionIDLimit

	for len(b) > 0 {
		paramIDInt, l, err := quicvarint.Parse(b)
		if err != nil {
			return err
		}
		paramID := transportParameterID(paramIDInt)
		b = b[l:]
		paramLen, l, err := quicvarint.Parse(b)
		if err != nil {
			return err
		}
		b = b[l:]
		if uint64(len(b)) < paramLen {
			return fmt.Errorf("remaining length (%d) smaller than parameter length (%d)", len(b), paramLen)
		}
		parameterIDs = append(parameterIDs, paramID)
		p.TransportParameterIDs = append(p.TransportParameterIDs, uint64(paramID))
		switch paramID {
		case maxIdleTimeoutParameterID,
			maxUDPPayloadSizeParameterID,
			initialMaxDataParameterID,
			initialMaxStreamDataBidiLocalParameterID,
			initialMaxStreamDataBidiRemoteParameterID,
			initialMaxStreamDataUniParameterID,
			initialMaxStreamsBidiParameterID,
			initialMaxStreamsUniParameterID,
			maxAckDelayParameterID,
			maxDatagramFrameSizeParameterID,
			ackDelayExponentParameterID,
			activeConnectionIDLimitParameterID,
			minAckDelayParameterID:
			if err := p.readNumericTransportParameter(b, paramID, int(paramLen)); err != nil {
				return err
			}
			b = b[paramLen:]
		case preferredAddressParameterID:
			if sentBy == protocol.PerspectiveClient {
				return errors.New("client sent a preferred_address")
			}
			if err := p.readPreferredAddress(b, int(paramLen)); err != nil {
				return err
			}
			b = b[paramLen:]
		case disableActiveMigrationParameterID:
			if paramLen != 0 {
				return fmt.Errorf("wrong length for disable_active_migration: %d (expected empty)", paramLen)
			}
			p.DisableActiveMigration = true
		case statelessResetTokenParameterID:
			if sentBy == protocol.PerspectiveClient {
				return errors.New("client sent a stateless_reset_token")
			}
			if paramLen != 16 {
				return fmt.Errorf("wrong length for stateless_reset_token: %d (expected 16)", paramLen)
			}
			var token protocol.StatelessResetToken
			if len(b) < len(token) {
				return io.EOF
			}
			copy(token[:], b)
			b = b[len(token):]
			p.StatelessResetToken = &token
		case originalDestinationConnectionIDParameterID:
			if sentBy == protocol.PerspectiveClient {
				return errors.New("client sent an original_destination_connection_id")
			}
			if paramLen > protocol.MaxConnIDLen {
				return protocol.ErrInvalidConnectionIDLen
			}
			p.OriginalDestinationConnectionID = protocol.ParseConnectionID(b[:paramLen])
			b = b[paramLen:]
			readOriginalDestinationConnectionID = true
		case initialSourceConnectionIDParameterID:
			if paramLen > protocol.MaxConnIDLen {
				return protocol.ErrInvalidConnectionIDLen
			}
			p.InitialSourceConnectionID = protocol.ParseConnectionID(b[:paramLen])
			b = b[paramLen:]
			readInitialSourceConnectionID = true
		case retrySourceConnectionIDParameterID:
			if sentBy == protocol.PerspectiveClient {
				return errors.New("client sent a retry_source_connection_id")
			}
			if paramLen > protocol.MaxConnIDLen {
				return protocol.ErrInvalidConnectionIDLen
			}
			connID := protocol.ParseConnectionID(b[:paramLen])
			b = b[paramLen:]
			p.RetrySourceConnectionID = &connID
		case resetStreamAtParameterID, legacyResetStreamAtParameterID:
			if paramLen != 0 {
				return fmt.Errorf("wrong length for reset_stream_at: %d (expected empty)", paramLen)
			}
			p.EnableResetStreamAt = true
			b = b[paramLen:]
		case greaseQuicBitParameterID:
			// RFC 9287: the grease_quic_bit transport parameter is sent with an empty value.
			if paramLen != 0 {
				return fmt.Errorf("wrong length for grease_quic_bit: %d (expected empty)", paramLen)
			}
			p.GreaseQuicBit = true
			b = b[paramLen:]
		default:
			if fromSessionTicket {
				// A ticket might contain a parameter for an extension supported by an older
				// version of this endpoint. If we can't parse it, don't resume with it.
				return fmt.Errorf("unknown transport parameter %#x in session ticket", paramID)
			}
			b = b[paramLen:]
		}
	}

	// min_ack_delay must be less or equal to max_ack_delay
	if p.MinAckDelay != nil && *p.MinAckDelay > p.MaxAckDelay {
		return fmt.Errorf("min_ack_delay (%s) is greater than max_ack_delay (%s)", *p.MinAckDelay, p.MaxAckDelay)
	}
	if !fromSessionTicket {
		if sentBy == protocol.PerspectiveServer && !readOriginalDestinationConnectionID {
			return errors.New("missing original_destination_connection_id")
		}
		if p.MaxUDPPayloadSize == 0 {
			p.MaxUDPPayloadSize = protocol.MaxByteCount
		}
		if !readInitialSourceConnectionID {
			return errors.New("missing initial_source_connection_id")
		}
	}

	// check that every transport parameter was sent at most once
	slices.Sort(parameterIDs)
	for i := range len(parameterIDs) - 1 {
		if parameterIDs[i] == parameterIDs[i+1] {
			return fmt.Errorf("received duplicate transport parameter %#x", parameterIDs[i])
		}
	}

	return nil
}

func (p *TransportParameters) readPreferredAddress(b []byte, expectedLen int) error {
	remainingLen := len(b)
	pa := &PreferredAddress{}
	if len(b) < 4+2+16+2+1 {
		return io.EOF
	}
	var ipv4 [4]byte
	copy(ipv4[:], b[:4])
	port4 := binary.BigEndian.Uint16(b[4:])
	b = b[4+2:]
	if port4 != 0 && ipv4 != [4]byte{} {
		pa.IPv4 = netip.AddrPortFrom(netip.AddrFrom4(ipv4), port4)
	}
	var ipv6 [16]byte
	copy(ipv6[:], b[:16])
	port6 := binary.BigEndian.Uint16(b[16:])
	if port6 != 0 && ipv6 != [16]byte{} {
		pa.IPv6 = netip.AddrPortFrom(netip.AddrFrom16(ipv6), port6)
	}
	b = b[16+2:]
	connIDLen := int(b[0])
	b = b[1:]
	if connIDLen == 0 || connIDLen > protocol.MaxConnIDLen {
		return fmt.Errorf("invalid connection ID length: %d", connIDLen)
	}
	if len(b) < connIDLen+len(pa.StatelessResetToken) {
		return io.EOF
	}
	pa.ConnectionID = protocol.ParseConnectionID(b[:connIDLen])
	b = b[connIDLen:]
	copy(pa.StatelessResetToken[:], b)
	b = b[len(pa.StatelessResetToken):]
	if bytesRead := remainingLen - len(b); bytesRead != expectedLen {
		return fmt.Errorf("expected preferred_address to be %d long, read %d bytes", expectedLen, bytesRead)
	}
	p.PreferredAddress = pa
	return nil
}

func (p *TransportParameters) readNumericTransportParameter(b []byte, paramID transportParameterID, expectedLen int) error {
	val, l, err := quicvarint.Parse(b)
	if err != nil {
		return fmt.Errorf("error while reading transport parameter %d: %s", paramID, err)
	}
	if l != expectedLen {
		return fmt.Errorf("inconsistent transport parameter length for transport parameter %#x", paramID)
	}
	//nolint:exhaustive // This only covers the numeric transport parameters.
	switch paramID {
	case initialMaxStreamDataBidiLocalParameterID:
		p.InitialMaxStreamDataBidiLocal = protocol.ByteCount(val)
	case initialMaxStreamDataBidiRemoteParameterID:
		p.InitialMaxStreamDataBidiRemote = protocol.ByteCount(val)
	case initialMaxStreamDataUniParameterID:
		p.InitialMaxStreamDataUni = protocol.ByteCount(val)
	case initialMaxDataParameterID:
		p.InitialMaxData = protocol.ByteCount(val)
	case initialMaxStreamsBidiParameterID:
		p.MaxBidiStreamNum = protocol.StreamNum(val)
		if p.MaxBidiStreamNum > protocol.MaxStreamCount {
			return fmt.Errorf("initial_max_streams_bidi too large: %d (maximum %d)", p.MaxBidiStreamNum, protocol.MaxStreamCount)
		}
	case initialMaxStreamsUniParameterID:
		p.MaxUniStreamNum = protocol.StreamNum(val)
		if p.MaxUniStreamNum > protocol.MaxStreamCount {
			return fmt.Errorf("initial_max_streams_uni too large: %d (maximum %d)", p.MaxUniStreamNum, protocol.MaxStreamCount)
		}
	case maxIdleTimeoutParameterID:
		p.MaxIdleTimeout = max(protocol.MinRemoteIdleTimeout, time.Duration(val)*time.Millisecond)
	case maxUDPPayloadSizeParameterID:
		if val < 1200 {
			return fmt.Errorf("invalid value for max_udp_payload_size: %d (minimum 1200)", val)
		}
		p.MaxUDPPayloadSize = protocol.ByteCount(val)
	case ackDelayExponentParameterID:
		if val > protocol.MaxAckDelayExponent {
			return fmt.Errorf("invalid value for ack_delay_exponent: %d (maximum %d)", val, protocol.MaxAckDelayExponent)
		}
		p.AckDelayExponent = uint8(val)
	case maxAckDelayParameterID:
		if val > uint64(protocol.MaxMaxAckDelay/time.Millisecond) {
			return fmt.Errorf("invalid value for max_ack_delay: %dms (maximum %dms)", val, protocol.MaxMaxAckDelay/time.Millisecond)
		}
		p.MaxAckDelay = time.Duration(val) * time.Millisecond
	case activeConnectionIDLimitParameterID:
		if val < 2 {
			return fmt.Errorf("invalid value for active_connection_id_limit: %d (minimum 2)", val)
		}
		p.ActiveConnectionIDLimit = val
	case maxDatagramFrameSizeParameterID:
		p.MaxDatagramFrameSize = protocol.ByteCount(val)
	case minAckDelayParameterID:
		mad := time.Duration(val) * time.Microsecond
		if mad < 0 {
			mad = math.MaxInt64
		}
		p.MinAckDelay = &mad
	default:
		return fmt.Errorf("TransportParameter BUG: transport parameter %d not found", paramID)
	}
	return nil
}

// Marshal the transport parameters
// Marshal the transport parameters, in the default order.
func (p *TransportParameters) Marshal(pers protocol.Perspective) []byte {
	return p.MarshalWithConfig(pers, nil, nil)
}

// MarshalWithConfig marshals the transport parameters.
//
// If order is nil, the parameters are marshaled in the default order,
// preceded by a randomly generated GREASE parameter (matching the behavior of quic-go).
//
// If order is non-empty, only the parameters whose IDs are contained in order
// are marshaled in the given order (parameters that are not set are skipped),
// followed by all remaining set parameters in the default order.
// No random GREASE parameter is added in this mode; use extra to add GREASE
// or other custom parameters with full control.
//
// extra contains additional transport parameters (ID -> raw value) that are
// appended at the end, sorted by ID. This is used for GREASE and custom parameters.
func (p *TransportParameters) MarshalWithConfig(pers protocol.Perspective, order []uint64, extra map[uint64][]byte) []byte {
	// Typical Transport Parameters consume around 110 bytes, depending on the exact values,
	// especially the lengths of the Connection IDs.
	// Allocate 256 bytes, so we won't have to grow the slice in any case.
	b := make([]byte, 0, 256)

	if len(order) > 0 {
		// Ordered mode: emit exactly the parameters listed in order (if set), then the remaining
		// parameters in the default order. No random GREASE parameter is added.
		emitted := make(map[transportParameterID]struct{}, len(order))
		for _, id := range order {
			paramID := transportParameterID(id)
			if _, ok := emitted[paramID]; ok {
				continue
			}
			var ok bool
			b, ok = p.marshalParam(b, paramID, pers, true)
			if ok {
				emitted[paramID] = struct{}{}
			}
		}
		for _, paramID := range defaultParameterOrder {
			if _, ok := emitted[paramID]; ok {
				continue
			}
			var ok bool
			b, ok = p.marshalParam(b, paramID, pers, false)
			if ok {
				emitted[paramID] = struct{}{}
			}
		}
	} else {
		// Default mode (same behavior as upstream quic-go):
		// add a greased value
		random := make([]byte, 18)
		rand.Read(random)
		b = quicvarint.Append(b, 27+31*uint64(random[0]))
		length := random[1] % 16
		b = quicvarint.Append(b, uint64(length))
		b = append(b, random[2:2+length]...)

		// initial_max_stream_data_bidi_local
		b = p.marshalVarintParam(b, initialMaxStreamDataBidiLocalParameterID, uint64(p.InitialMaxStreamDataBidiLocal))
		// initial_max_stream_data_bidi_remote
		b = p.marshalVarintParam(b, initialMaxStreamDataBidiRemoteParameterID, uint64(p.InitialMaxStreamDataBidiRemote))
		// initial_max_stream_data_uni
		b = p.marshalVarintParam(b, initialMaxStreamDataUniParameterID, uint64(p.InitialMaxStreamDataUni))
		// initial_max_data
		b = p.marshalVarintParam(b, initialMaxDataParameterID, uint64(p.InitialMaxData))
		// initial_max_bidi_streams
		b = p.marshalVarintParam(b, initialMaxStreamsBidiParameterID, uint64(p.MaxBidiStreamNum))
		// initial_max_uni_streams
		b = p.marshalVarintParam(b, initialMaxStreamsUniParameterID, uint64(p.MaxUniStreamNum))
		// idle_timeout
		b = p.marshalVarintParam(b, maxIdleTimeoutParameterID, uint64(p.MaxIdleTimeout/time.Millisecond))
		// max_udp_payload_size
		if p.MaxUDPPayloadSize > 0 {
			b = p.marshalVarintParam(b, maxUDPPayloadSizeParameterID, uint64(p.MaxUDPPayloadSize))
		}
		// max_ack_delay
		// Only send it if is different from the default value.
		if p.MaxAckDelay != protocol.DefaultMaxAckDelay {
			b = p.marshalVarintParam(b, maxAckDelayParameterID, uint64(p.MaxAckDelay/time.Millisecond))
		}
		// ack_delay_exponent
		// Only send it if is different from the default value.
		if p.AckDelayExponent != protocol.DefaultAckDelayExponent {
			b = p.marshalVarintParam(b, ackDelayExponentParameterID, uint64(p.AckDelayExponent))
		}
		// disable_active_migration
		if p.DisableActiveMigration {
			b = quicvarint.Append(b, uint64(disableActiveMigrationParameterID))
			b = quicvarint.Append(b, 0)
		}
		if pers == protocol.PerspectiveServer {
			// stateless_reset_token
			if p.StatelessResetToken != nil {
				b = quicvarint.Append(b, uint64(statelessResetTokenParameterID))
				b = quicvarint.Append(b, 16)
				b = append(b, p.StatelessResetToken[:]...)
			}
			// original_destination_connection_id
			b = quicvarint.Append(b, uint64(originalDestinationConnectionIDParameterID))
			b = quicvarint.Append(b, uint64(p.OriginalDestinationConnectionID.Len()))
			b = append(b, p.OriginalDestinationConnectionID.Bytes()...)
			// preferred_address
			if p.PreferredAddress != nil {
				b = quicvarint.Append(b, uint64(preferredAddressParameterID))
				b = quicvarint.Append(b, 4+2+16+2+1+uint64(p.PreferredAddress.ConnectionID.Len())+16)
				if p.PreferredAddress.IPv4.IsValid() {
					ipv4 := p.PreferredAddress.IPv4.Addr().As4()
					b = append(b, ipv4[:]...)
					b = binary.BigEndian.AppendUint16(b, p.PreferredAddress.IPv4.Port())
				} else {
					b = append(b, make([]byte, 6)...)
				}
				if p.PreferredAddress.IPv6.IsValid() {
					ipv6 := p.PreferredAddress.IPv6.Addr().As16()
					b = append(b, ipv6[:]...)
					b = binary.BigEndian.AppendUint16(b, p.PreferredAddress.IPv6.Port())
				} else {
					b = append(b, make([]byte, 18)...)
				}
				b = append(b, uint8(p.PreferredAddress.ConnectionID.Len()))
				b = append(b, p.PreferredAddress.ConnectionID.Bytes()...)
				b = append(b, p.PreferredAddress.StatelessResetToken[:]...)
			}
		}
		// active_connection_id_limit
		// A value of 0 is invalid per RFC 9000 and is skipped (the peer then uses the default).
		if p.ActiveConnectionIDLimit != 0 && p.ActiveConnectionIDLimit != protocol.DefaultActiveConnectionIDLimit {
			b = p.marshalVarintParam(b, activeConnectionIDLimitParameterID, p.ActiveConnectionIDLimit)
		}
		// initial_source_connection_id
		b = quicvarint.Append(b, uint64(initialSourceConnectionIDParameterID))
		b = quicvarint.Append(b, uint64(p.InitialSourceConnectionID.Len()))
		b = append(b, p.InitialSourceConnectionID.Bytes()...)
		// retry_source_connection_id
		if pers == protocol.PerspectiveServer && p.RetrySourceConnectionID != nil {
			b = quicvarint.Append(b, uint64(retrySourceConnectionIDParameterID))
			b = quicvarint.Append(b, uint64(p.RetrySourceConnectionID.Len()))
			b = append(b, p.RetrySourceConnectionID.Bytes()...)
		}
		// QUIC datagrams
		if p.MaxDatagramFrameSize != protocol.InvalidByteCount {
			b = p.marshalVarintParam(b, maxDatagramFrameSizeParameterID, uint64(p.MaxDatagramFrameSize))
		}
		// QUIC Stream Resets with Partial Delivery
		if p.EnableResetStreamAt {
			b = quicvarint.Append(b, uint64(resetStreamAtParameterID))
			b = quicvarint.Append(b, 0)
		}
		if p.MinAckDelay != nil {
			b = p.marshalVarintParam(b, minAckDelayParameterID, uint64(*p.MinAckDelay/time.Microsecond))
		}
		// grease_quic_bit (RFC 9287)
		if p.GreaseQuicBit {
			b = quicvarint.Append(b, uint64(greaseQuicBitParameterID))
			b = quicvarint.Append(b, 0)
		}
	}

	if pers == protocol.PerspectiveClient && len(AdditionalTransportParametersClient) > 0 {
		for _, k := range sortedKeys(AdditionalTransportParametersClient) {
			v := AdditionalTransportParametersClient[k]
			b = quicvarint.Append(b, k)
			b = quicvarint.Append(b, uint64(len(v)))
			b = append(b, v...)
		}
	}

	if len(extra) > 0 {
		for _, k := range sortedKeys(extra) {
			v := extra[k]
			b = quicvarint.Append(b, k)
			b = quicvarint.Append(b, uint64(len(v)))
			b = append(b, v...)
		}
	}

	return b
}

// defaultParameterOrder is the order in which the transport parameters are marshaled
// when no explicit order is given. This matches the behavior of upstream quic-go.
var defaultParameterOrder = []transportParameterID{
	initialMaxStreamDataBidiLocalParameterID,
	initialMaxStreamDataBidiRemoteParameterID,
	initialMaxStreamDataUniParameterID,
	initialMaxDataParameterID,
	initialMaxStreamsBidiParameterID,
	initialMaxStreamsUniParameterID,
	maxIdleTimeoutParameterID,
	maxUDPPayloadSizeParameterID,
	maxAckDelayParameterID,
	ackDelayExponentParameterID,
	disableActiveMigrationParameterID,
	statelessResetTokenParameterID,
	originalDestinationConnectionIDParameterID,
	preferredAddressParameterID,
	activeConnectionIDLimitParameterID,
	initialSourceConnectionIDParameterID,
	retrySourceConnectionIDParameterID,
	maxDatagramFrameSizeParameterID,
	resetStreamAtParameterID,
	minAckDelayParameterID,
	greaseQuicBitParameterID,
}

func sortedKeys[V any](m map[uint64]V) []uint64 {
	keys := make([]uint64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// marshalParam marshals a single transport parameter, if it is set.
// The second return value indicates whether the parameter was marshaled.
// If force is true, parameters that are usually omitted when they match the protocol default
// (max_ack_delay, ack_delay_exponent, active_connection_id_limit) are emitted anyway.
// This is used when an explicit parameter order was requested, where the caller expects
// exactly the listed parameters to be sent.
func (p *TransportParameters) marshalParam(b []byte, id transportParameterID, pers protocol.Perspective, force bool) ([]byte, bool) {
	//nolint:exhaustive // This only covers the known transport parameters.
	switch id {
	case initialMaxStreamDataBidiLocalParameterID:
		return p.marshalVarintParam(b, id, uint64(p.InitialMaxStreamDataBidiLocal)), true
	case initialMaxStreamDataBidiRemoteParameterID:
		return p.marshalVarintParam(b, id, uint64(p.InitialMaxStreamDataBidiRemote)), true
	case initialMaxStreamDataUniParameterID:
		return p.marshalVarintParam(b, id, uint64(p.InitialMaxStreamDataUni)), true
	case initialMaxDataParameterID:
		return p.marshalVarintParam(b, id, uint64(p.InitialMaxData)), true
	case initialMaxStreamsBidiParameterID:
		return p.marshalVarintParam(b, id, uint64(p.MaxBidiStreamNum)), true
	case initialMaxStreamsUniParameterID:
		return p.marshalVarintParam(b, id, uint64(p.MaxUniStreamNum)), true
	case maxIdleTimeoutParameterID:
		return p.marshalVarintParam(b, id, uint64(p.MaxIdleTimeout/time.Millisecond)), true
	case maxUDPPayloadSizeParameterID:
		if p.MaxUDPPayloadSize == 0 {
			return b, false
		}
		return p.marshalVarintParam(b, id, uint64(p.MaxUDPPayloadSize)), true
	case maxAckDelayParameterID:
		// Only send it if it is different from the default value.
		if p.MaxAckDelay == 0 || (!force && p.MaxAckDelay == protocol.DefaultMaxAckDelay) {
			return b, false
		}
		return p.marshalVarintParam(b, id, uint64(p.MaxAckDelay/time.Millisecond)), true
	case ackDelayExponentParameterID:
		// Only send it if it is different from the default value.
		if p.AckDelayExponent == 0 || (!force && p.AckDelayExponent == protocol.DefaultAckDelayExponent) {
			return b, false
		}
		return p.marshalVarintParam(b, id, uint64(p.AckDelayExponent)), true
	case disableActiveMigrationParameterID:
		if !p.DisableActiveMigration {
			return b, false
		}
		b = quicvarint.Append(b, uint64(id))
		b = quicvarint.Append(b, 0)
		return b, true
	case statelessResetTokenParameterID:
		if pers != protocol.PerspectiveServer || p.StatelessResetToken == nil {
			return b, false
		}
		b = quicvarint.Append(b, uint64(id))
		b = quicvarint.Append(b, 16)
		b = append(b, p.StatelessResetToken[:]...)
		return b, true
	case originalDestinationConnectionIDParameterID:
		if pers != protocol.PerspectiveServer {
			return b, false
		}
		b = quicvarint.Append(b, uint64(id))
		b = quicvarint.Append(b, uint64(p.OriginalDestinationConnectionID.Len()))
		b = append(b, p.OriginalDestinationConnectionID.Bytes()...)
		return b, true
	case preferredAddressParameterID:
		if pers != protocol.PerspectiveServer || p.PreferredAddress == nil {
			return b, false
		}
		b = quicvarint.Append(b, uint64(id))
		b = quicvarint.Append(b, 4+2+16+2+1+uint64(p.PreferredAddress.ConnectionID.Len())+16)
		if p.PreferredAddress.IPv4.IsValid() {
			ipv4 := p.PreferredAddress.IPv4.Addr().As4()
			b = append(b, ipv4[:]...)
			b = binary.BigEndian.AppendUint16(b, p.PreferredAddress.IPv4.Port())
		} else {
			b = append(b, make([]byte, 6)...)
		}
		if p.PreferredAddress.IPv6.IsValid() {
			ipv6 := p.PreferredAddress.IPv6.Addr().As16()
			b = append(b, ipv6[:]...)
			b = binary.BigEndian.AppendUint16(b, p.PreferredAddress.IPv6.Port())
		} else {
			b = append(b, make([]byte, 18)...)
		}
		b = append(b, uint8(p.PreferredAddress.ConnectionID.Len()))
		b = append(b, p.PreferredAddress.ConnectionID.Bytes()...)
		b = append(b, p.PreferredAddress.StatelessResetToken[:]...)
		return b, true
	case activeConnectionIDLimitParameterID:
		if p.ActiveConnectionIDLimit == 0 || (!force && p.ActiveConnectionIDLimit == protocol.DefaultActiveConnectionIDLimit) {
			return b, false
		}
		return p.marshalVarintParam(b, id, p.ActiveConnectionIDLimit), true
	case initialSourceConnectionIDParameterID:
		b = quicvarint.Append(b, uint64(id))
		b = quicvarint.Append(b, uint64(p.InitialSourceConnectionID.Len()))
		b = append(b, p.InitialSourceConnectionID.Bytes()...)
		return b, true
	case retrySourceConnectionIDParameterID:
		if pers != protocol.PerspectiveServer || p.RetrySourceConnectionID == nil {
			return b, false
		}
		b = quicvarint.Append(b, uint64(id))
		b = quicvarint.Append(b, uint64(p.RetrySourceConnectionID.Len()))
		b = append(b, p.RetrySourceConnectionID.Bytes()...)
		return b, true
	case maxDatagramFrameSizeParameterID:
		// QUIC datagrams
		if p.MaxDatagramFrameSize == protocol.InvalidByteCount {
			return b, false
		}
		return p.marshalVarintParam(b, id, uint64(p.MaxDatagramFrameSize)), true
	case resetStreamAtParameterID:
		// QUIC Stream Resets with Partial Delivery
		if !p.EnableResetStreamAt {
			return b, false
		}
		b = quicvarint.Append(b, uint64(id))
		b = quicvarint.Append(b, 0)
		return b, true
	case minAckDelayParameterID:
		if p.MinAckDelay == nil {
			return b, false
		}
		return p.marshalVarintParam(b, id, uint64(*p.MinAckDelay/time.Microsecond)), true
	case greaseQuicBitParameterID:
		// RFC 9287
		if !p.GreaseQuicBit {
			return b, false
		}
		b = quicvarint.Append(b, uint64(id))
		b = quicvarint.Append(b, 0)
		return b, true
	default:
		return b, false
	}
}

func (p *TransportParameters) marshalVarintParam(b []byte, id transportParameterID, val uint64) []byte {
	b = quicvarint.Append(b, uint64(id))
	b = quicvarint.Append(b, uint64(quicvarint.Len(val)))
	return quicvarint.Append(b, val)
}

// MarshalForSessionTicket marshals the transport parameters we save in the session ticket.
// When sending a 0-RTT enabled TLS session tickets, we need to save the transport parameters.
// The client will remember the transport parameters used in the last session,
// and apply those to the 0-RTT data it sends.
// Saving the transport parameters in the ticket gives the server the option to reject 0-RTT
// if the transport parameters changed.
// Since the session ticket is encrypted, the serialization format is defined by the server.
// For convenience, we use the same format that we also use for sending the transport parameters.
func (p *TransportParameters) MarshalForSessionTicket(b []byte) []byte {
	b = quicvarint.Append(b, transportParameterMarshalingVersion)

	// initial_max_stream_data_bidi_local
	b = p.marshalVarintParam(b, initialMaxStreamDataBidiLocalParameterID, uint64(p.InitialMaxStreamDataBidiLocal))
	// initial_max_stream_data_bidi_remote
	b = p.marshalVarintParam(b, initialMaxStreamDataBidiRemoteParameterID, uint64(p.InitialMaxStreamDataBidiRemote))
	// initial_max_stream_data_uni
	b = p.marshalVarintParam(b, initialMaxStreamDataUniParameterID, uint64(p.InitialMaxStreamDataUni))
	// initial_max_data
	b = p.marshalVarintParam(b, initialMaxDataParameterID, uint64(p.InitialMaxData))
	// initial_max_bidi_streams
	b = p.marshalVarintParam(b, initialMaxStreamsBidiParameterID, uint64(p.MaxBidiStreamNum))
	// initial_max_uni_streams
	b = p.marshalVarintParam(b, initialMaxStreamsUniParameterID, uint64(p.MaxUniStreamNum))
	// active_connection_id_limit
	b = p.marshalVarintParam(b, activeConnectionIDLimitParameterID, p.ActiveConnectionIDLimit)
	// max_datagram_frame_size
	if p.MaxDatagramFrameSize != protocol.InvalidByteCount {
		b = p.marshalVarintParam(b, maxDatagramFrameSizeParameterID, uint64(p.MaxDatagramFrameSize))
	}
	// reset_stream_at
	if p.EnableResetStreamAt {
		b = quicvarint.Append(b, uint64(resetStreamAtParameterID))
		b = quicvarint.Append(b, 0)
	}
	return b
}

// UnmarshalFromSessionTicket unmarshals transport parameters from a session ticket.
func (p *TransportParameters) UnmarshalFromSessionTicket(b []byte) error {
	version, l, err := quicvarint.Parse(b)
	if err != nil {
		return err
	}
	if version != transportParameterMarshalingVersion {
		return fmt.Errorf("unknown transport parameter marshaling version: %d", version)
	}
	return p.unmarshal(b[l:], protocol.PerspectiveServer, true)
}

// ValidFor0RTT checks if the transport parameters match those saved in the session ticket.
func (p *TransportParameters) ValidFor0RTT(saved *TransportParameters) bool {
	if saved.MaxDatagramFrameSize != protocol.InvalidByteCount && (p.MaxDatagramFrameSize == protocol.InvalidByteCount || p.MaxDatagramFrameSize < saved.MaxDatagramFrameSize) {
		return false
	}
	if saved.EnableResetStreamAt && !p.EnableResetStreamAt {
		return false
	}
	return p.InitialMaxStreamDataBidiLocal >= saved.InitialMaxStreamDataBidiLocal &&
		p.InitialMaxStreamDataBidiRemote >= saved.InitialMaxStreamDataBidiRemote &&
		p.InitialMaxStreamDataUni >= saved.InitialMaxStreamDataUni &&
		p.InitialMaxData >= saved.InitialMaxData &&
		p.MaxBidiStreamNum >= saved.MaxBidiStreamNum &&
		p.MaxUniStreamNum >= saved.MaxUniStreamNum &&
		p.ActiveConnectionIDLimit == saved.ActiveConnectionIDLimit
}

// ValidForUpdate checks that the new transport parameters don't reduce limits after resuming a 0-RTT connection.
// It is only used on the client side.
func (p *TransportParameters) ValidForUpdate(saved *TransportParameters) bool {
	if saved.MaxDatagramFrameSize != protocol.InvalidByteCount && (p.MaxDatagramFrameSize == protocol.InvalidByteCount || p.MaxDatagramFrameSize < saved.MaxDatagramFrameSize) {
		return false
	}
	if saved.EnableResetStreamAt && !p.EnableResetStreamAt {
		return false
	}
	return p.ActiveConnectionIDLimit >= saved.ActiveConnectionIDLimit &&
		p.InitialMaxData >= saved.InitialMaxData &&
		p.InitialMaxStreamDataBidiLocal >= saved.InitialMaxStreamDataBidiLocal &&
		p.InitialMaxStreamDataBidiRemote >= saved.InitialMaxStreamDataBidiRemote &&
		p.InitialMaxStreamDataUni >= saved.InitialMaxStreamDataUni &&
		p.MaxBidiStreamNum >= saved.MaxBidiStreamNum &&
		p.MaxUniStreamNum >= saved.MaxUniStreamNum
}

// String returns a string representation, intended for logging.
func (p *TransportParameters) String() string {
	logString := "&wire.TransportParameters{OriginalDestinationConnectionID: %s, InitialSourceConnectionID: %s, "
	logParams := []any{p.OriginalDestinationConnectionID, p.InitialSourceConnectionID}
	if p.RetrySourceConnectionID != nil {
		logString += "RetrySourceConnectionID: %s, "
		logParams = append(logParams, p.RetrySourceConnectionID)
	}
	logString += "InitialMaxStreamDataBidiLocal: %d, InitialMaxStreamDataBidiRemote: %d, InitialMaxStreamDataUni: %d, InitialMaxData: %d, MaxBidiStreamNum: %d, MaxUniStreamNum: %d, MaxIdleTimeout: %s, AckDelayExponent: %d, MaxAckDelay: %s, ActiveConnectionIDLimit: %d"
	logParams = append(logParams, []any{p.InitialMaxStreamDataBidiLocal, p.InitialMaxStreamDataBidiRemote, p.InitialMaxStreamDataUni, p.InitialMaxData, p.MaxBidiStreamNum, p.MaxUniStreamNum, p.MaxIdleTimeout, p.AckDelayExponent, p.MaxAckDelay, p.ActiveConnectionIDLimit}...)
	if p.StatelessResetToken != nil { // the client never sends a stateless reset token
		logString += ", StatelessResetToken: %#x"
		logParams = append(logParams, *p.StatelessResetToken)
	}
	if p.MaxDatagramFrameSize != protocol.InvalidByteCount {
		logString += ", MaxDatagramFrameSize: %d"
		logParams = append(logParams, p.MaxDatagramFrameSize)
	}
	logString += ", EnableResetStreamAt: %t"
	logParams = append(logParams, p.EnableResetStreamAt)
	if p.MinAckDelay != nil {
		logString += ", MinAckDelay: %s"
		logParams = append(logParams, *p.MinAckDelay)
	}
	logString += "}"
	return fmt.Sprintf(logString, logParams...)
}
