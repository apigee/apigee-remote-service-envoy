// This package is just a shim to eliminate the github.com/hashicorp/hcl dependency
package hcl

// Parse does nothing
func Parse(x string) (*NodeHolder, error) {
	return nil, nil
}

// DecodeObject does nothing
func DecodeObject(*map[string]interface{}, interface{}) error {
	return nil
}

// NodeHolder holds a Node
type NodeHolder struct {
	Node interface{}
}
