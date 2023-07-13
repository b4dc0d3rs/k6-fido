package k6fido

import (
	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/k6fido", new(K6Fido))
}

type K6Fido struct {
}
