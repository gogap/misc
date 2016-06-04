package tls

type Option func(*Options)

type Options struct {
	Host []string

	CACertfile string
	CAKeyfile  string

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

func CAFile(caCertfile, caKeyfile string) Option {
	return func(o *Options) {
		o.CACertfile = caCertfile
		o.CAKeyfile = caKeyfile
	}
}

func CAData(cert, key []byte) Option {
	return func(o *Options) {
		o.CACert = cert
		o.CAKey = key
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
