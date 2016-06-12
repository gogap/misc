package tls

import (
	"io/ioutil"
	"os"
)

type Option func(*Options)

type Options struct {
	Host []string

	CACert []byte
	CAKey  []byte

	CommonName         string
	Locality, Province []string

	Country, Organization, OrganizationalUnit []string

	BitSize int

	IsServerCert bool
}

func Host(host ...string) Option {
	return func(o *Options) {
		o.Host = host
	}
}

func CACert(cert, key []byte) Option {
	return func(o *Options) {
		o.CACert = cert
		o.CAKey = key
	}
}

func CACertFromFile(certfile, keyfile string) Option {
	return func(o *Options) {
		o.CACert, _ = ioutil.ReadFile(certfile)
		o.CAKey, _ = ioutil.ReadFile(keyfile)
	}
}

func CACertFromEnv(certEnvKey, keyEnvKey string) Option {
	return func(o *Options) {
		certfile := os.Getenv(certEnvKey)
		keyfile := os.Getenv(keyEnvKey)

		o.CACert, _ = ioutil.ReadFile(certfile)
		o.CAKey, _ = ioutil.ReadFile(keyfile)
	}
}

func CACertFromProvider(fn func() (cert, key []byte, err error)) Option {
	return func(o *Options) {
		c, k, e := fn()
		if e != nil {
			o.CACert = c
			o.CAKey = k
		}
	}
}

func CommonName(commonName string) Option {
	return func(o *Options) {
		o.CommonName = commonName
	}
}

func Organization(org ...string) Option {
	return func(o *Options) {
		o.Organization = org
	}
}

func OrganizationalUnit(orgUnit ...string) Option {
	return func(o *Options) {
		o.OrganizationalUnit = orgUnit
	}
}

func Country(country ...string) Option {
	return func(o *Options) {
		o.Country = country
	}
}

func Locality(locality ...string) Option {
	return func(o *Options) {
		o.Locality = locality
	}
}
func Province(province ...string) Option {
	return func(o *Options) {
		o.Province = province
	}
}

func BitSize(size int) Option {
	return func(o *Options) {
		o.BitSize = size
	}
}

func IsServerCert(isServerCert bool) Option {
	return func(o *Options) {
		o.IsServerCert = isServerCert
	}
}
