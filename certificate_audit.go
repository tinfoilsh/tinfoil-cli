package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
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

func decodeHashDomains(domains []string) (string, error) {
	sort.Slice(domains, func(i, j int) bool {
		return domains[i][:2] < domains[j][:2]
	})

	var encodedData string
	for _, domain := range domains {
		domain = strings.Split(domain, ".")[0]
		encodedData += domain[2:]
	}

	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	hashBytes, err := encoder.DecodeString(strings.ToUpper(encodedData))
	if err != nil {
		return "", fmt.Errorf("failed to decode base32: %v", err)
	}
	return string(hashBytes), nil
}

func attestationFromCertificate(cert *x509.Certificate, enclaveHost string) (*attestation.Document, string, error) {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("public key is not an ECDSA key")
	}
	keyFP := tlsutil.KeyFP(pubKey)

	var attDomains []string
	var hashAttDomains []string
	for _, name := range cert.DNSNames {
		if strings.HasSuffix(name, ".att.tinfoil.sh") {
			attDomains = append(attDomains, name)
			log.Debugf("Attestation domain: %s", name)
		} else if strings.HasSuffix(name, ".hatt.tinfoil.sh") {
			hashAttDomains = append(hashAttDomains, name)
			log.Debugf("Hash attestation domain: %s", name)
		}
	}

	if len(attDomains) > 0 {
		att, err := dcode.Decode(attDomains)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decode attestation: %v", err)
		}
		return att, keyFP, nil
	}

	if len(hashAttDomains) > 0 {
		if enclaveHost == "" {
			return nil, "", fmt.Errorf("certificate contains only hash attestation domains; use -s flag to specify server for attestation fetch")
		}

		certAttHash, err := decodeHashDomains(hashAttDomains)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decode hash attestation: %v", err)
		}
		log.Debugf("Certificate attestation hash: %s", certAttHash)

		att, err := attestation.Fetch(enclaveHost)
		if err != nil {
			return nil, "", fmt.Errorf("failed to fetch attestation from server: %v", err)
		}
		serverAttHash := att.Hash()
		log.Debugf("Server attestation hash: %s", serverAttHash)

		if certAttHash != serverAttHash {
			return nil, "", fmt.Errorf("attestation hash mismatch: cert=%s server=%s", certAttHash, serverAttHash)
		}
		log.Infof("Attestation hash verified: %s", certAttHash)
		return att, keyFP, nil
	}

	return nil, "", fmt.Errorf("no attestation domains found in certificate")
}

var certificateAuditCmd = &cobra.Command{
	Use:   "certificate audit",
	Short: "Audit enclave certificate",
	Run: func(cmd *cobra.Command, args []string) {
		var cert *x509.Certificate
		var enclaveHost string
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
			enclaveHost = strings.TrimSuffix(server, ":443")
			serverAddr := server
			if !strings.Contains(serverAddr, ":") {
				serverAddr += ":443"
			}

			conn, err := tls.Dial("tcp", serverAddr, nil)
			if err != nil {
				log.Fatalf("Failed to connect to server: %v", err)
			}

			certs := conn.ConnectionState().PeerCertificates
			if len(certs) == 0 {
				log.Fatal("No certificates found")
			}
			cert = certs[0]
		}

		att, certKeyFP, err := attestationFromCertificate(cert, enclaveHost)
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
