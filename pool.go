package pemtools

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

var pemData []byte

type CertificatePool struct {
	certs                     []*Certificate
	bySubjectKeyID            map[string][]int
	byName                    map[string][]int
	dups, exp, invalid, total int
}

func newCertificatePool() *CertificatePool {
	cp := CertificatePool{
		bySubjectKeyID: make(map[string][]int),
		byName:         make(map[string][]int),
	}
	return &cp
}

func NewPoolFromFile(fpath string) (*CertificatePool, error) {
	pemData, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	pool := CertificatePool{
		bySubjectKeyID: make(map[string][]int),
		byName:         make(map[string][]int),
	}
	pool.appendCertsFromPEM(pemData)
	//err = populatePool(pool, pemData)
	return &pool, nil
}

func poolFromFile(fpath string) (*CertificatePool, error) {
	pemData, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	pool := CertificatePool{
		bySubjectKeyID: make(map[string][]int),
		byName:         make(map[string][]int),
	}
	pool.appendCertsFromPEM(pemData)

	return &pool, nil
}

func NewCARootsPoolFromFile(fpath string) (*CertificatePool, error) {
	pool, err := poolFromFile(fpath)
	if err != nil {
		return nil, err
	}

	// As bundle represents system roots, build chains and check validity
	var parentCert *Certificate
	var isChild bool
	certList := make([]*Certificate, 0)

	for _, v := range pool.certs {
		parents, _, err := pool.findVerifiedParents(v)
		isChild = false

		if err != nil && len(parents) == 0 {
			v.SetError(err)
		} else {
			parentCert = pool.certs[parents[0]]
			isChild = parentCert.AddChild(v)
			v.AddParent(parentCert)
		}

		if !isChild {
			certList = append(certList, v)
		}
		// fmt.Printf("%s\n", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ec.Certificate().Raw})))
		// }
		// fmt.Printf("% 3d - %+v\t\t%+v\t\t%+v\n", i, parents, v.Certificate().Subject.CommonName, err)
	}
	pool.certs = certList
	// fmt.Printf("cert Length: %d - certList Length: %d\n", len(pool.certs), len(certList))
	return pool, nil
}

func (p *CertificatePool) findVerifiedParents(cert *Certificate) (parents []int, errCert *Certificate, err error) {
	if p == nil {
		return
	}
	var candidates []int

	if len(cert.Certificate().AuthorityKeyId) > 0 {
		candidates = p.bySubjectKeyID[string(cert.Certificate().AuthorityKeyId)]
	}
	if len(candidates) == 0 {
		candidates = p.byName[string(cert.Certificate().RawIssuer)]
	}

	for _, c := range candidates {
		if err = cert.Certificate().CheckSignatureFrom(p.certs[c].Certificate()); err == nil {
			parents = append(parents, c)
		} else {
			errCert = p.certs[c]
		}
	}

	return
}

func printWithIndent(certs []*Certificate, indent string) {
	for _, c := range certs {
		if err := c.IsValid(); err != nil {
			fmt.Printf("%sX %s (%s) - %s\n", indent, c.DisplayName, strings.Join(c.c.Subject.Country, " "), err)
			continue
		}
		fmt.Printf("%s- %s (%s)\n", indent, c.DisplayName, strings.Join(c.c.Subject.Country, " "))
		printWithIndent(c.children, indent+"  ")
	}
}

func (p *CertificatePool) DebugOut() {
	printWithIndent(p.certs, "")
	fmt.Printf("Total certificates: %d\n", p.total)
	fmt.Printf("Duplicate certificates: %d\n", p.dups)
	fmt.Printf("Expired certificates: %d\n", p.countExpired())
}

func (p *CertificatePool) countExpired() int {
	expired := 0
	for _, c := range p.certs {
		if c.Expired() {
			expired++
		}
	}
	return expired
}

func (p *CertificatePool) appendCertsFromPEM(pemCerts []byte) {
	for len(pemCerts) > 0 {
		p.total++
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := NewCertificateFromBytes(block.Bytes)
		if err != nil {
			continue
		}

		p.AddCert(cert)
	}
}

func (p *CertificatePool) AddCert(cert *Certificate) {
	if cert == nil {
		log.Println("Error: tying to add nil Certificate to CertificatePool")
		return
	}

	// Check that the certificate isn't being added twice.
	if p.contains(cert) {
		p.dups++
		return
	}

	n := len(p.certs)
	p.certs = append(p.certs, cert)

	if len(cert.Certificate().SubjectKeyId) > 0 {
		keyId := string(cert.Certificate().SubjectKeyId)
		p.bySubjectKeyID[keyId] = append(p.bySubjectKeyID[keyId], n)
	}
	name := string(cert.Certificate().RawSubject)
	p.byName[name] = append(p.byName[name], n)
}

func (p *CertificatePool) contains(cert *Certificate) bool {
	if p == nil {
		return false
	}

	candidates := p.byName[string(cert.Certificate().RawSubject)]
	for _, c := range candidates {
		if p.certs[c].Certificate().Equal(cert.Certificate()) {
			return true
		}
	}

	return false
}

//func populatePool(p *x509.CertPool, data []byte) error {
//	var certPem *pem.Block
//
//	for {
//		certPem, data = pem.Decode(data)
//		if certPem == nil {
//			break
//		}
//		cert, err := NewCertificateFromBytes(certPem.Bytes)
//		if err != nil {
//			log.Println(err)
//			continue
//		}
//		p.AppendCertsFromPEM()
//		sha := sha1.Sum(cert.Certificate().Raw)
//		fmt.Println("SHASUM:", sha)
//		//// fingerPrints = append(fingerPrints, fmt.Sprintf("%x", sha))
//		//fPrints[fmt.Sprintf("%x", sha)] = append(fPrints[fmt.Sprintf("%x", sha)], cert)
//		//fSub[cert.DisplayName] = append(fSub[cert.DisplayName], cert)
//		//bundle.c = append(bundle.c, cert)
//		//bundle.issuers[cert.GetIssuer().String()] = append(bundle.issuers[cert.GetIssuer().String()], cert)
//	}
//	return nil
//}
