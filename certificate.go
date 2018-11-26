package pemtools

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"
)

type CertificateType int

const (
	RootCA CertificateType = iota
	IntermediateCA
	Regular
)

type Certificate struct {
	c           *x509.Certificate
	parents     []*Certificate
	children    []*Certificate
	DisplayName string
	Type        CertificateType
	Valid       *ValidDuration
	invalid     *InvalidCertificate
}

type InvalidCertificate struct {
	reason string
}

type ValidDuration struct {
	From, To time.Time
}

func (i *InvalidCertificate) Error() string {
	return i.reason
}

func NewCertificateFromBytes(data []byte) (*Certificate, error) {
	c, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}

	return newCertificate(c)
}

func newCertificate(c *x509.Certificate) (*Certificate, error) {
	cert := &Certificate{c: c}
	cert.Valid = newValidPeriod(c.NotBefore, c.NotAfter)
	if c.IsCA {
		if string(c.RawSubject) == string(c.RawIssuer) {
			cert.Type = RootCA
		} else {
			cert.Type = IntermediateCA
		}
	}
	err := cert.SetDisplayName(c.Subject)
	return cert, err
}

func (c *Certificate) Certificate() *x509.Certificate {
	return c.c
}

func (c *Certificate) SetDisplayName(subject pkix.Name) error {
	if subject.CommonName != "" {
		c.DisplayName = subject.CommonName
		return nil
	}
	if c.DisplayName = strings.Join(subject.Organization, ", "); c.DisplayName != "" {
		return nil
	}
	if c.DisplayName = strings.Join(subject.OrganizationalUnit, ", "); c.DisplayName != "" {
		return nil
	}
	c.DisplayName = string(subject.String())
	return nil
}

func (c *Certificate) IsValid() error {
	if c.Expired() {
		return fmt.Errorf("Certificate has expired. Not After: %s", c.Valid.To)
	}
	if c.invalid != nil {
		return c.invalid
	}
	return nil
}

func (c *Certificate) validMarker(good, bad string) string {
	if c.invalid != nil {
		return bad
	}
	if c.Expired() {
		return bad
	}
	return good
}

func (c *Certificate) AddParent(cert *Certificate) {
	c.parents = append(c.parents, cert)
}

func (c *Certificate) AddChild(cert *Certificate) bool {
	if !c.Certificate().Equal(cert.Certificate()) {
		c.children = append(c.children, cert)
		return true
	}
	return false
}

func (c *Certificate) SetError(e error) {
	c.invalid = &InvalidCertificate{e.Error()}
}

func (c *Certificate) Expired() bool {
	return c.Valid.expired()
}

func (v *ValidDuration) expired() bool {
	now := time.Now()

	if v.From.Before(now) && v.To.After(now) {
		return false
	}
	return true
}

func newValidPeriod(before, after time.Time) *ValidDuration {
	return &ValidDuration{
		From: before,
		To:   after,
	}
}
