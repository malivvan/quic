# quic [![godoc](https://godoc.org/github.com/malivvan/quic?status.svg)](https://godoc.org/github.com/malivvan/quic) ![test](https://github.com/malivvan/quic/workflows/test/badge.svg) [![Coverage Status](https://coveralls.io/repos/github/malivvan/quic/badge.svg?branch=master)](https://coveralls.io/github/malivvan/quic?branch=master) [![Release](https://img.shields.io/github/v/release/malivvan/quic.svg?sort=semver)](https://github.com/malivvan/quic/releases/latest) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

fork of [github.com/quic-go/quic-go](https://github.com/quic-go/quic-go) and [github.com/quic-go/webtransport-go](https://github.com/quic-go/webtransport-go) supporting fingerprinting and browser impersonation

- `.` github.com/quic-go/quic-go v0.61.0 (with the fork's fingerprinting / browser-mimicry changes re-applied on top)
- `./qpack` github.com/quic-go/qpack v0.6.0
- `./webtransport` github.com/quic-go/webtransport-go v0.12.0 (with the fork's fingerprinting / browser-mimicry changes re-applied on top)
- `./webtransport/httpsfv` github.com/dunglas/httpsfv 4cd96cab33c4a28ca20f9a9a92d43ce85a9bf7ad

 > changes from github.com/pagpeter/quic-go v0.0.0-20260120153640-0de4e3b8377b are ported

## Features

* Unreliable Datagram Extension ([RFC 9221](https://datatracker.ietf.org/doc/html/rfc9221))
* Datagram Packetization Layer Path MTU Discovery (DPLPMTUD, [RFC 8899](https://datatracker.ietf.org/doc/html/rfc8899))
* QUIC Version 2 ([RFC 9369](https://datatracker.ietf.org/doc/html/rfc9369))
* QUIC Event Logging using qlog ([draft-ietf-quic-qlog-main-schema](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/) and [draft-ietf-quic-qlog-quic-events](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/))
* QUIC Stream Resets with Partial Delivery ([draft-ietf-quic-reliable-stream-reset](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-07))
* WebTransport over HTTP/3 ([draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/))
