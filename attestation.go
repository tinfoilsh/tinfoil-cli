package main

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/tinfoilsh/tfshim/dcode"
	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/client"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
)

func init() {
	rootCmd.AddCommand(attestationCmd)
}

var attestationCmd = &cobra.Command{
	Use:     "attestation",
	Aliases: []string{"att"},
	Short:   "Attestation commands",
}

func tlsConnection(enclaveHost string) (*tls.ConnectionState, error) {
	conn, err := tls.Dial("tcp", enclaveHost, &tls.Config{})
	if err != nil {
		return nil, fmt.Errorf("dialing enclave: %v", err)
	}
	cs := conn.ConnectionState()
	return &cs, nil
}

type auditRecord struct {
	Timestamp string `json:"timestamp"`

	Enclave string `json:"enclave"`
	Repo    string `json:"repo,omitempty"`
	Digest  string `json:"digest,omitempty"`

	Measurements struct {
		Sigstore attestation.Measurement  `json:"sigstore,omitempty"` // Measurement from sigstore bundle
		Enclave  *attestation.Measurement `json:"enclave,omitempty"`  // Measurement from enclave attestation over HTTP
		Cert     string                   `json:"cert,omitempty"`     // Measurement from enclave attestation in certificate
	} `json:"measurements"`

	Keys struct {
		Enclave    string `json:"enclave,omitempty"`    // Public key from enclave attestation over HTTP
		Connection string `json:"connection,omitempty"` // Public key from connection
		Cert       string `json:"cert,omitempty"`       // Public key from dcode attestation in certificate
	} `json:"keys"`

	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func verifyAttestation(l *log.Logger) (*auditRecord, error) {
	if enclaveHost == "" {
		routerClient, err := client.NewDefaultClient()
		if err != nil {
			return nil, fmt.Errorf("getting router: %v", err)
		}
		enclaveHost = routerClient.Enclave()
		l.Printf("Using auto selected router: %s", enclaveHost)
	}

	var auditRec auditRecord
	auditRec.Timestamp = time.Now().UTC().Format(time.RFC3339)
	auditRec.Enclave = enclaveHost

	var codeMeasurements *attestation.Measurement
	if repo != "" {
		l.Printf("Fetching latest release for %s", repo)
		digest, err := github.FetchLatestDigest(repo)
		if err != nil {
			return nil, fmt.Errorf("fetching latest release: %v", err)
		}
		auditRec.Repo = repo
		auditRec.Digest = digest

		l.Printf("Fetching sigstore bundle from %s for digest %s", repo, digest)
		bundleBytes, err := github.FetchAttestationBundle(repo, digest)
		if err != nil {
			return nil, fmt.Errorf("fetching attestation bundle: %v", err)
		}

		l.Println("Fetching trust root")
		trustRootJSON, err := sigstore.FetchTrustRoot()
		if err != nil {
			return nil, fmt.Errorf("fetching trust root: %v", err)
		}

		l.Println("Verifying code measurements")
		codeMeasurements, err = sigstore.VerifyAttestation(trustRootJSON, bundleBytes, digest, repo)
		if err != nil {
			return nil, fmt.Errorf("sigstore verify: %v", err)
		}
		auditRec.Measurements.Sigstore = *codeMeasurements
	} else {
		l.Warn("No repo specified, skipping code measurements")
		auditRec.Status = "enclave_only"
	}

	l.Printf("Fetching attestation doc from %s", enclaveHost)
	remoteAttestation, err := attestation.Fetch(enclaveHost)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation document: %v", err)
	}

	l.Println("Verifying enclave measurements")
	verification, err := remoteAttestation.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifying attestation document: %v", err)
	}
	auditRec.Measurements.Enclave = verification.Measurement
	auditRec.Keys.Enclave = verification.TLSPublicKeyFP
	l.Printf("Public key fingerprint: %s", verification.TLSPublicKeyFP)
	if verification.HPKEPublicKey != "" {
		l.Printf("HPKE public key: %s", verification.HPKEPublicKey)
	}

	// Get remote pubkey fingerprint
	cs, err := tlsConnection(enclaveHost + ":443")
	if err != nil {
		return nil, fmt.Errorf("fetching remote public key fingerprint: %v", err)
	}
	pubkeyFP, err := attestation.ConnectionCertFP(*cs)
	if err != nil {
		return nil, fmt.Errorf("fetching remote public key fingerprint: %v", err)
	}
	auditRec.Keys.Connection = pubkeyFP
	l.Debugf("Remote public key fingerprint: %s", pubkeyFP)

	cert := cs.PeerCertificates[0]

	l.Debugf("DNSNames %v", cert.DNSNames)

	var hpke_key_domains []string
	var att_domains []string
	var hash_att_domains []string

	for _, name := range cert.DNSNames {
		if strings.HasSuffix(name, ".hpke.tinfoil.sh") {
			hpke_key_domains = append(hpke_key_domains, name)
		} else if strings.HasSuffix(name, ".att.tinfoil.sh") {
			att_domains = append(att_domains, name)
		} else if strings.HasSuffix(name, ".hatt.tinfoil.sh") {
			hash_att_domains = append(hash_att_domains, name)
		}
	}

	l.Debugf("hpke_key_domains %v, att_domains %v, hash_att_domains %v", hpke_key_domains, att_domains, hash_att_domains)

	if len(att_domains) > 0 {
		dcodeAttestation, err := dcode.Decode(att_domains)
		if err == nil {
			dcodeAttestationMaterial, err := dcodeAttestation.Verify()
			if err != nil {
				return nil, fmt.Errorf("verifying attestation: %v", err)
			}
			auditRec.Keys.Cert = dcodeAttestationMaterial.TLSPublicKeyFP
			auditRec.Measurements.Cert = dcodeAttestationMaterial.TLSPublicKeyFP
		} else {
			log.Warnf("Failed to decode dcode attestation: %v", err)
		}
	}

	// Compare remote public key fingerprint with attestation public key
	if pubkeyFP != verification.TLSPublicKeyFP {
		auditRec.Status = "FAILED"
		auditRec.Error = "Remote public key fingerprint does not match attestation public key"
		log.Printf("Remote public key fingerprint does not match attestation public key")
	}

	if repo != "" && codeMeasurements != nil && verification.Measurement != nil {
		if err := codeMeasurements.Equals(verification.Measurement); err != nil {
			auditRec.Status = "fail"
			auditRec.Error = fmt.Sprintf("PCR register mismatch: %v", err)
			log.Printf("PCR register mismatch. Verification failed: %v", err)
			log.Printf("Code: %+v", codeMeasurements)
			log.Printf("Enclave: %+v", verification.Measurement)
		} else {
			l.Println("Measurements match")
		}
	} else {
		l.Printf("Enclave measurement: %+v", verification.Measurement)
	}

	if auditRec.Status == "" {
		auditRec.Status = "ok"
	}

	return &auditRec, nil
}
