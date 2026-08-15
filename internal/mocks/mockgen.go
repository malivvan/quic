//go:build gomock || generate

package mocks

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination short_header_sealer.go github.com/malivvan/quic/internal/handshake ShortHeaderSealer"
//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination short_header_opener.go github.com/malivvan/quic/internal/handshake ShortHeaderOpener"
//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination long_header_opener.go github.com/malivvan/quic/internal/handshake LongHeaderOpener"
//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination crypto_setup.go github.com/malivvan/quic/internal/handshake CryptoSetup"
//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package mocks -destination congestion.go github.com/malivvan/quic/internal/congestion SendAlgorithmWithDebugInfos"
//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\" -package mockackhandler -destination ackhandler/sent_packet_handler.go github.com/malivvan/quic/internal/ackhandler SentPacketHandler"
