package cache

import (
	"io"

	"github.com/rs/zerolog"
)

// testLogger returns a no-op logger for testing
func testLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}
