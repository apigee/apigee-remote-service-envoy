// This package is just a shim to eliminate the github.com/hashicorp/hcl dependency
package printer

import (
	"github.com/spf13/afero"
)

func Fprint(afero.File, interface{}) error {
	return nil
}
