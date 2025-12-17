package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tinfoilsh/tfshim/dcode"
	tlsutil "github.com/tinfoilsh/tfshim/tls"
	"github.com/tinfoilsh/verifier/attestation"
)

var (
	server   string
	certFile string
)

func init() {
	certificateAuditCmd.PersistentFlags().StringVarP(&server, "server", "s", "", "Server to connect to")
	certificateAuditCmd.PersistentFlags().StringVarP(&certFile, "cert", "c", "", "Path to PEM encoded certificate file")
	rootCmd.AddCommand(certificateAuditCmd)
}

func attestationFromCertificate(cert *x509.Certificate) (*attestation.Document, string, error) {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("public key is not an ECDSA key")
	}
	keyFP := tlsutil.KeyFP(pubKey)

	var attDomains []string
	for _, name := range cert.DNSNames {
		if strings.HasSuffix(name, ".att.tinfoil.sh") {
			attDomains = append(attDomains, name)
			log.Debugf("Attestation domain: %s", name)
		}
	}

	if len(attDomains) == 0 {
		return nil, "", fmt.Errorf("no attestation domains found in certificate")
	}

	att, err := dcode.Decode(attDomains)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode attestation: %v", err)
	}
	return att, keyFP, nil
}

var certificateAuditCmd = &cobra.Command{
	Use:   "certificate audit",
	Short: "Audit enclave certificate",
	Run: func(cmd *cobra.Command, args []string) {
		var cert *x509.Certificate
		if certFile != "" {
			certBytes, err := os.ReadFile(certFile)
			if err != nil {
				log.Fatalf("Failed to read certificate file: %v", err)
			}
			block, _ := pem.Decode(certBytes)
			if block == nil {
				log.Fatalf("Failed to decode certificate")
			}
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Fatalf("Failed to parse certificate: %v", err)
			}
		} else {
			if server == "" {
				log.Fatal("Server address is required")
			}
			if !strings.Contains(server, ":") {
				server += ":443"
			}

			conn, err := tls.Dial("tcp", server, nil)
			if err != nil {
				log.Fatalf("Failed to connect to server: %v", err)
			}

			certs := conn.ConnectionState().PeerCertificates
			if len(certs) == 0 {
				log.Fatal("No certificates found")
			}
			cert = certs[0]
		}

		att, certKeyFP, err := attestationFromCertificate(cert)
		if err != nil {
			log.Fatalf("Failed to get attestation from certificate: %v", err)
		}

		measurement, err := att.Verify()
		if err != nil {
			log.Fatalf("Failed to verify attestation: %v", err)
		}

		if certKeyFP != measurement.TLSPublicKeyFP {
			log.Fatalf("Certificate key fingerprint does not match attestation key fingerprint")
		} else {
			log.Infof("Certificate-attestation key match: %s", certKeyFP)
		}

		log.Infof("Measurement: %+v", measurement.Measurement)
	},
}
