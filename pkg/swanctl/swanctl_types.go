package swanctl

import (
	"os"
)

const (
	IPsecConfFile        = "/etc/swanctl/conf.d/k8s-nodes.conf"
	CurrentNode          = "controller-0"
	CertificatePrefix    = "system-ipsec-certificate-"
	CertificateExtension = ".crt"
	SystemLocalCACert0   = "system-local-ca-0.crt"
	SystemLocalCACert1   = "system-local-ca-1.crt"
)

type ConfigurationFile struct {
	Connections []any
	File        *os.File
	Hostname    string
	LocalNet    string
	LocalAddr   string
}
