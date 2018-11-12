package cacert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"regexp"
	"time"
)

type CertificateType int

const (
	RootCA CertificateType = iota
	IntermediateCA
	Regular
)

type CACertificate struct {
	Filename    *string
	DisplayName string
	Certificate *x509.Certificate
	Invalid     bool
	Issues      []*CACertificate
}

func (c *CACertificate) Expired() bool {
	if c.Certificate.NotAfter.Before(time.Now()) {
		c.Invalid = true
		return true
	}
	return false
}

// func register(c *CACertificate) {

// 		c.DisplayName = fmt.Sprintf("%x", c.Certificate.SerialNumber.Bytes())
// 	}
// 	issuer := c.Certificate.Issuer.String()
// 	if c.Certificate.IsCA {
// 		if c.Certificate.Subject.String() == issuer {
// 			c.Type = RootCA
// 		} else {
// 			c.Type = IntermediateCA
// 		}
// 	} else {
// 		c.Type = Regular
// 	}
// 	certificateByIssuer[issuer] = append(certificateByIssuer[issuer], c)
// }

func (c *CACertificate) Type() CertificateType {
	if c.Certificate.IsCA {
		if c.GetSubject().String() == c.GetIssuer().String() {
			return RootCA
		} else {
			return IntermediateCA
		}
	}
	return Regular
}

func (c *CACertificate) GetIssuer() *pkix.Name {
	return &c.Certificate.Issuer
}

func (c *CACertificate) GetSubject() *pkix.Name {
	return &c.Certificate.Subject
}

func fromCertificate(c *x509.Certificate) *CACertificate {
	cert := &CACertificate{
		Certificate: c,
		Issues:      make([]*CACertificate, 0),
	}
	if cert.DisplayName = c.Subject.CommonName; cert.DisplayName == "" {
		cert.DisplayName = fmt.Sprintf("%s (%x)", c.Subject.String(), c.SerialNumber.Bytes())
	}
	return cert
}

func (c *CACertificate) WritePEM(outputDir, expiredDir string) error {
	if c.Filename == nil {
		c.Filename = generateFilename(c.DisplayName)
		fmt.Println(*c.Filename)
	}
	return nil
}

func generateFilename(name string) *string {
	r := regexp.MustCompile(`[^a-zA-Z0-9\.]+`)
	f := fmt.Sprintf("%s.pem", r.ReplaceAllString(name, "_"))
	return &f
}

func ParseDER(b []byte) (*CACertificate, error) {
	c, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, err
	}
	cert := fromCertificate(c)
	return cert, nil
}

// func ListIssuers() {
// 	for k, v := range certificateByIssuer {
// 		fmt.Printf("Issuer '%s', issued %d certificates\n", k, len(v))
// 	}
// 	// spew.Dump(certificateByIssuer)
// }
