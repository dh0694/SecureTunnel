package devicetrust

import (
	"crypto/x509"

	"securetunnel/server/internal/model"
)

// sanUPNs returns the UPN otherName values from the subject alternative names.
func sanUPNs(c *x509.Certificate) []string { return model.SANUPNs(c) }
