package mcassoc

import (
	"errors"
)

var (
	ERR_SKIN_TOO_SMALL = errors.New(`skin must be at least 8x8`)
)
