package certbundle

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/devopsbrett/pemtools/cacert"
)

type CertBundle struct {
	c       []*cacert.CACertificate
	issuers map[string][]*cacert.CACertificate
}

func BundleFromFile(filename string) (*CertBundle, error) {
	bundle := new(CertBundle)
	bundle.issuers = make(map[string][]*cacert.CACertificate)
	var certDERBlock *pem.Block
	certPEMBlock, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		cert, err := cacert.ParseDER(certDERBlock.Bytes)
		if err != nil {
			log.Println(err)
			continue
		}
		bundle.c = append(bundle.c, cert)
		bundle.issuers[cert.GetIssuer().String()] = append(bundle.issuers[cert.GetIssuer().String()], cert)
	}
	return bundle, nil
}

func (c *CertBundle) PrintHierarchy() string {
	certList := c.c
	fmt.Printf("Certificates in bundle: %d\nCertificates in certlist: %d\n", len(c.c), len(certList))
	certList = certList[:len(certList)-1]
	fmt.Printf("Certificates in bundle: %d\nCertificates in certlist: %d\n", len(c.c), len(certList))

	for _, v := range c.c {
		// if len(c.issuers[v.GetSubject().String()]) > 0 {
		// 	continue
		// }
		// if v.Type() == cacert.RootCA {
		// 	fmt.Printf("%s - (Root CA)\n", v.DisplayName)
		// }
		fmt.Printf("%x\n", v.Certificate.SerialNumber.Bytes())
	}

	return ""
}

func (c *CertBundle) OutputPEMFiles(outputDir, expiredDir string) error {
	outputExpired := expiredDir != ""
	fmt.Printf("%+v\n", outputExpired)
	for _, cert := range c.c {
		if err := cert.WritePEM(outputDir, expiredDir); err != nil {
			return err
		}
	}
	return nil
}
