//go:build race

package wire

// raceEnabled reports whether the race detector is enabled.
// The "race" build tag is set by "go test -race".
const raceEnabled = true
