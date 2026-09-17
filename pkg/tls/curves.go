package tls

import (
	"fmt"
	"strconv"
	"strings"

	cryptotls "crypto/tls"
)

// ParseCurvePreferences validates numeric Go crypto/tls CurveID values without
// maintaining a version-specific list of curve names in this repository.
func ParseCurvePreferences(values []string) ([]cryptotls.CurveID, error) {
	if len(values) == 0 {
		return nil, nil
	}

	result := make([]cryptotls.CurveID, 0, len(values))
	seen := make(map[cryptotls.CurveID]struct{}, len(values))
	for _, value := range values {
		id, err := strconv.ParseInt(value, 10, 32)
		if err != nil || id < 1 || id > 65535 {
			return nil, fmt.Errorf("TLS curve preference %q is invalid", value)
		}
		curve := cryptotls.CurveID(id)
		if strings.HasPrefix(curve.String(), "CurveID(") {
			return nil, fmt.Errorf("TLS curve preference %q is unsupported by this Go version", value)
		}
		if _, ok := seen[curve]; ok {
			return nil, fmt.Errorf("duplicate TLS curve preference %q", value)
		}
		seen[curve] = struct{}{}
		result = append(result, curve)
	}
	return result, nil
}
