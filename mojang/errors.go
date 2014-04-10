package mojang

import (
	"errors"
)

var (
	ERR_NO_SUCH_USER     = errors.New(`no such user`)
	ERR_TOO_MANY_RESULTS = errors.New(`too many results`)
)
