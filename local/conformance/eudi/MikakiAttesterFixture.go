// Test-only software attester for the disposable eudi-dev source copy.
package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var mikakiAttesterKey *ecdsa.PrivateKey
var mikakiAttesterChain []*x509.Certificate

func (w *Wallet) mikakiProbeKeyAttestations(a credentialRequestAttempt, proofs credentialProofs) error {
	if mikakiAttesterKey == nil || os.Getenv("MIKAKI_EUDI_KEY_NEGATIVES") != "1" {
		return nil
	}
	compact := proofs.Values[0]
	if proofs.Type == "jwt" {
		h, err := base64.RawURLEncoding.DecodeString(strings.Split(compact, ".")[0])
		if err != nil {
			return err
		}
		var header map[string]any
		if err := json.Unmarshal(h, &header); err != nil {
			return err
		}
		compact, _ = header["key_attestation"].(string)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(compact, ".")[1])
	if err != nil {
		return err
	}
	var original map[string]any
	if err := json.Unmarshal(raw, &original); err != nil {
		return err
	}
	nonce, _ := original["nonce"].(string)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	untrustedCA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "Untrusted fixture attester CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDer, err := x509.CreateCertificate(rand.Reader, ca, ca, &untrustedCA.PublicKey, untrustedCA)
	if err != nil {
		return err
	}
	ca, err = x509.ParseCertificate(caDer)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "Untrusted fixture attester"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &other.PublicKey, untrustedCA)
	if err != nil {
		return err
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	cases := []string{"wrong_nonce", "bad_signature", "untrusted_chain", "ambiguous_keys"}
	if proofs.Type == "jwt" {
		cases = append(cases, "holder_mismatch")
	}
	for _, name := range cases {
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
		payload["mikaki_negative_case"] = name
		signer := mikakiAttesterKey
		chain := mikakiAttesterChain
		switch name {
		case "wrong_nonce":
			payload["nonce"] = "signed-but-unissued-nonce"
		case "untrusted_chain":
			signer = other
			chain = []*x509.Certificate{leaf, ca}
		case "ambiguous_keys":
			payload["attested_keys"] = []any{mock.SigningJWKMap(&a.proofKeys[0].PublicKey), mock.SigningJWKMap(&other.PublicKey)}
		case "holder_mismatch":
			payload["attested_keys"] = []any{mock.SigningJWKMap(&other.PublicKey)}
		}
		attestation, err := signJWT(map[string]any{"alg": "ES256", "typ": "key-attestation+jwt", "x5c": buildJWSX5C(chain)}, payload, signer)
		if err != nil {
			return err
		}
		if name == "bad_signature" {
			parts := strings.Split(attestation, ".")
			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				return err
			}
			sig[0] ^= 1
			parts[2] = base64.RawURLEncoding.EncodeToString(sig)
			attestation = strings.Join(parts, ".")
		}
		invalid := credentialProofs{Type: "attestation", Values: []string{attestation}}
		if proofs.Type == "jwt" {
			values, err := createProofJWTs(a.proofKeys[:1], a.issuer, a.clientID, nonce, map[string]any{"key_attestation": attestation})
			if err != nil {
				return err
			}
			invalid = credentialProofs{Type: "jwt", Values: values}
		}
		// Upstream creates fresh DPoP proofs and handles nonce challenges for each probe.
		result, err := w.sendCredentialRequest(a, invalid)
		expected := "invalid_proof"
		if name == "wrong_nonce" {
			expected = "invalid_nonce"
		}
		if err == nil || result == nil || result["error"] != expected || !strings.Contains(err.Error(), expected) {
			return fmt.Errorf("key-attestation probe %s did not fail as expected", name)
		}
	}
	return nil
}

func mikakiFixtureJWTProof() bool {
	return mikakiAttesterKey != nil && os.Getenv("MIKAKI_EUDI_ATTESTER_PROOF") == "jwt"
}

func mikakiAttestationMaterial(w *Wallet) (*ecdsa.PrivateKey, []*x509.Certificate) {
	if w == nil {
		return nil, nil
	}
	if mikakiAttesterKey != nil {
		return mikakiAttesterKey, mikakiAttesterChain
	}
	return w.IssuerKey, w.CertChain
}

// Private keys stay inside the Go Wallet process and its isolated fixture directory.
func init() {
	dir := os.Getenv("MIKAKI_EUDI_ATTESTER_DIR")
	if dir == "" {
		return
	}
	must := func(err error) {
		if err != nil {
			panic("disposable attester initialization failed")
		}
	}
	must(os.MkdirAll(dir, 0700))
	key := func(name string) *ecdsa.PrivateKey {
		path := filepath.Join(dir, name+".key")
		bytes, err := os.ReadFile(path)
		if err == nil {
			block, _ := pem.Decode(bytes)
			if block == nil {
				panic("invalid disposable attester key")
			}
			parsed, err := x509.ParseECPrivateKey(block.Bytes)
			must(err)
			return parsed
		}
		if !os.IsNotExist(err) {
			must(err)
		}
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		encoded, err := x509.MarshalECPrivateKey(generated)
		must(err)
		must(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0600))
		return generated
	}
	caKey := key("ca")
	mikakiAttesterKey = key("attester")
	serial := func() *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		must(err)
		return n
	}
	now := time.Now()
	caPath := filepath.Join(dir, "ca.pem")
	caBytes, err := os.ReadFile(caPath)
	if os.IsNotExist(err) {
		ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Disposable Wallet attester CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
		must(err)
		caBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		must(os.WriteFile(caPath, caBytes, 0600))
	} else {
		must(err)
	}
	block, _ := pem.Decode(caBytes)
	if block == nil {
		panic("invalid disposable attester CA")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	must(err)
	// Attester purpose is deliberately separate from the upstream mdoc/TLS certificates.
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Disposable software Wallet attester"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &mikakiAttesterKey.PublicKey, caKey)
	must(err)
	cert, err := x509.ParseCertificate(der)
	must(err)
	mikakiAttesterChain = []*x509.Certificate{cert, ca}
}
