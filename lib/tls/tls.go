package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

func GenerateCACertificate(opts ...Option) (certOut, keyOut []byte, err error) {

	options := Options{
		CommonName:         "GoGap Certification Authority",
		Country:            []string{"CN"},
		Province:           []string{"Beijing"},
		Locality:           []string{"Beijing"},
		Organization:       []string{"gogap.cn"},
		OrganizationalUnit: []string{"IT Department"},
		BitSize:            1024,
	}

	for _, opt := range opts {
		opt(&options)
	}

	template, err := newCertificate(options)
	if err != nil {
		return nil, nil, err
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign
	template.KeyUsage |= x509.KeyUsageKeyEncipherment
	template.KeyUsage |= x509.KeyUsageKeyAgreement

	var priv *rsa.PrivateKey

	if priv, err = rsa.GenerateKey(rand.Reader, options.BitSize); err != nil {
		return
	}

	var derBytes []byte

	if derBytes, err = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv); err != nil {
		return nil, nil, err
	}

	var cOut bytes.Buffer
	var kOut bytes.Buffer

	pem.Encode(&cOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(&kOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return cOut.Bytes(), kOut.Bytes(), nil
}

func GenerateCertificate(opts ...Option) (certOut, keyOut []byte, err error) {

	options := Options{
		Host:               []string{"localhost", "127.0.0.1"},
		Country:            []string{"CN"},
		Province:           []string{"Beijing"},
		Locality:           []string{"Beijing"},
		Organization:       []string{"gogap.cn"},
		OrganizationalUnit: []string{"IT Department"},
		BitSize:            1024,
		IsServerCert:       true,
	}

	for _, opt := range opts {
		opt(&options)
	}

	if !options.IsServerCert {
		options.Host = nil
	}

	var tlsCACert tls.Certificate

	if options.CACertfile != "" && options.CAKeyfile != "" {
		if tlsCACert, err = tls.LoadX509KeyPair(options.CACertfile, options.CAKeyfile); err != nil {
			return
		}
	} else if options.CACert != nil && options.CAKey != nil {
		certPEM, _ := pem.Decode(options.CACert)
		keyPEM, _ := pem.Decode(options.CAKey)

		if tlsCACert, err = tls.X509KeyPair(certPEM.Bytes, keyPEM.Bytes); err != nil {
			return
		}
	}

	var template *x509.Certificate
	if template, err = newCertificate(options); err != nil {
		return
	}

	for _, host := range options.Host {
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}

		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	var priv *rsa.PrivateKey
	if priv, err = rsa.GenerateKey(rand.Reader, options.BitSize); err != nil {
		return
	}

	var derBytes []byte
	if tlsCACert.Certificate == nil {

		if options.IsServerCert {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			template.KeyUsage = x509.KeyUsageDigitalSignature
		}

		if derBytes, err = x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv); err != nil {
			return
		}
	} else {
		var x509Cert *x509.Certificate
		if x509Cert, err = x509.ParseCertificate(tlsCACert.Certificate[0]); err != nil {
			return nil, nil, err
		}

		if derBytes, err = x509.CreateCertificate(rand.Reader, template, x509Cert, &priv.PublicKey, tlsCACert.PrivateKey); err != nil {
			return
		}
	}

	var cOut bytes.Buffer
	var kOut bytes.Buffer

	pem.Encode(&cOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(&kOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	certOut = cOut.Bytes()
	keyOut = kOut.Bytes()

	return
}

func newCertificate(opts Options) (cert *x509.Certificate, err error) {

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            opts.Country,
			Organization:       opts.Organization,
			OrganizationalUnit: opts.OrganizationalUnit,

			CommonName: opts.CommonName,

			Locality: opts.Locality,
			Province: opts.Province,
		},

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}

	cert = template

	return
}
