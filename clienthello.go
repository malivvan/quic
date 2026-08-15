package quic

import (
	"slices"

	"github.com/malivvan/quic/internal/handshake"
	"github.com/malivvan/quic/internal/protocol"
	"github.com/malivvan/quic/internal/wire"
	"github.com/malivvan/quic/quicvarint"
)

// maxClientHelloExtractSize caps the amount of ClientHello data extracted from the first
// Initial packet. ClientHellos are usually well below 4 KB; this is a sanity limit.
const maxClientHelloExtractSize = 64 * 1024

// extractClientHelloFromInitial decrypts the first Initial packet and returns the raw
// ClientHello bytes contained in it, if possible. data must contain the complete packet
// (header + payload); trailing bytes (e.g. from coalesced packets) are not allowed.
// This is a best-effort operation: any failure (undecryptable packet, ClientHello split
// across multiple packets, etc.) yields a nil return. The handshake layer accumulates the
// complete ClientHello across all fragments; see ConnectionState.ClientHello.
func extractClientHelloFromInitial(data []byte, hdr *wire.Header) []byte {
	if hdr.Type != protocol.PacketTypeInitial {
		return nil
	}
	if protocol.ByteCount(len(data)) < hdr.ParsedLen()+hdr.Length {
		return nil
	}
	// Only the packet itself (as bounded by the Length field) is decrypted.
	data = data[:hdr.ParsedLen()+hdr.Length]
	_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, hdr.Version)
	// unpackLongHeader mutates the packet data (header protection removal),
	// so operate on a copy.
	buf := slices.Clone(data)
	extHdr, parseErr := unpackLongHeader(opener, hdr, buf, false)
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return nil
	}
	extHdrLen := extHdr.ParsedLen()
	extHdr.PacketNumber = opener.DecodePacketNumber(extHdr.PacketNumber, extHdr.PacketNumberLen)
	decrypted, err := opener.Open(buf[extHdrLen:extHdrLen], buf[extHdrLen:], extHdr.PacketNumber, buf[:extHdrLen])
	if err != nil {
		return nil
	}
	return extractClientHelloFromFrames(decrypted)
}

// extractClientHelloFromFrames walks the frames of a decrypted Initial payload and
// concatenates the CRYPTO frame data (in order). Only contiguous data is concatenated;
// the result is a (possibly partial) ClientHello message.
func extractClientHelloFromFrames(payload []byte) []byte {
	var out []byte
	for len(payload) > 0 {
		firstByte := payload[0]
		if firstByte == 0x00 { // PADDING frame
			payload = payload[1:]
			continue
		}
		if firstByte != 0x06 { // not a CRYPTO frame
			break
		}
		payload = payload[1:]
		offset, n, err := quicvarint.Parse(payload)
		if err != nil {
			break
		}
		payload = payload[n:]
		dataLen, n, err := quicvarint.Parse(payload)
		if err != nil {
			break
		}
		payload = payload[n:]
		if uint64(len(payload)) < dataLen {
			break
		}
		// Only concatenate contiguous CRYPTO data.
		if offset == uint64(len(out)) && len(out)+int(dataLen) <= maxClientHelloExtractSize {
			out = append(out, payload[:dataLen]...)
		}
		payload = payload[dataLen:]
	}
	return out
}
