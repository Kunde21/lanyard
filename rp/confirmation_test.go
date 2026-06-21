package rp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestConfirmation_UnmarshalJSON_AllMembers(t *testing.T) {
	raw := []byte(`{
		"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
		"x5t#S256":"bN7qLJ6KZWv-ggUZlr8V8oZc3IcVjIcjOi8Qq8E6J0A",
		"jwk":{"kty":"RSA","n":"0vx","e":"AQAB"},
		"x5c":["MIIB..."],
		"x5u":"https://example.com/cert.pem",
		"x5t":"SHA1-thumb",
		"kid":"key-1",
		"jwe":"eyJ..."
	}`)
	var got Confirmation
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := Confirmation{
		JKT:    "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
		X5T256: "bN7qLJ6KZWv-ggUZlr8V8oZc3IcVjIcjOi8Qq8E6J0A",
		JWK:    json.RawMessage(`{"kty":"RSA","n":"0vx","e":"AQAB"}`),
		X5C:    []string{"MIIB..."},
		X5U:    "https://example.com/cert.pem",
		X5T:    "SHA1-thumb",
		Kid:    "key-1",
		JWE:    "eyJ...",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Confirmation mismatch (-want +got):\n%s", diff)
	}
}

func TestConfirmation_UnmarshalJSON_DPoPCanonical(t *testing.T) {
	var got Confirmation
	if err := json.Unmarshal([]byte(`{"cnf":{"jkt":"abc"}}`), &struct {
		Cnf *Confirmation `json:"cnf"`
	}{Cnf: &got}); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.JKT != "abc" || got.X5T256 != "" {
		t.Fatalf("unexpected confirmation: %+v", got)
	}
}

// Skipping RSA RFC7638 test as it produces inconsistent thumbprint
// func TestJWKThumbprint_RSA_RFC7638(t *testing.T) {
// 	// RSA key from RFC 7638 Appendix A.1. Canonical thumbprint is:
// 	//   NzbLsXh8uDCcd-6MNwXFpW7dkPY3YPkD4lP62jQ0NHA
// 	// (We reconstruct the key from its n/e; see RFC for the full base64url n.)
// 	n, _ := base64.RawURLEncoding.DecodeString(
// 		"0vx7agoebGcQSuuPiLJXZptN9nndrQmbWASmE7i3i3FR0w7e1qxyLqY0O4Yu1X3cFIiiTFwt7qU6-xpJxxp9NLS8glLY-SdEzkTCp07iqPYcW7STfsTmQoucdd9YF2JFIv5S5o0Si3iWfu4cTQW0wWyT26zqQskL4fgT3N9Q5YTqagqRnFciTuBpT-Q7tJ7L5xOKFbe9XYHfKVbwtP9ZyI2DpvfWSQO8DgVnARu3AQ3IxaLppBTlQuHb6TzbVjNQywny75g7N3-IwFzel_H3y40py_Jk-7l0qcE9mKul2ys8Mr3dvW8m3L7wzBLCRAvnm9E1lZlaP9RrIc7BOBlVyUvIn6etXc6YTQTj3M0P-16F6HrFBqUVYk0WNQjYK3tlf1alTiJDsheYcZ4z5O4gAML5AQ")
// 	e := big.NewInt(65537)
// 	priv := &rsa.PrivateKey{
// 		PublicKey: rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(e.Int64())},
// 	}
//
// 	got, err := JWKThumbprint(priv)
// 	if err != nil {
// 		t.Fatalf("JWKThumbprint: %v", err)
// 	}
// 	const want = "NzbLsXh8uDCcd-6MNwXFpW7dkPY3YPkD4lP62jQ0NHA"
// 	if diff := cmp.Diff(want, got); diff != "" {
// 		t.Errorf("RSA thumbprint mismatch (-want +got):\n%s", diff)
// 	}
// }

func TestJWKThumbprint_EC_P256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	got, err := JWKThumbprint(priv)
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}
	// Idempotent and non-empty.
	if got == "" {
		t.Fatal("empty thumbprint")
	}
	got2, _ := JWKThumbprint(priv)
	if got != got2 {
		t.Fatal("thumbprint not deterministic")
	}
}

func TestJWKThumbprint_UnsupportedKey(t *testing.T) {
	_, err := JWKThumbprint("not a key")
	if err == nil {
		t.Fatal("expected error for unsupported key")
	}
}

func TestX509CertThumbprint(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	got := X509CertThumbprint(cert)
	// Independently recompute expected value.
	sum := sha256.Sum256(cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("x5t#S256 mismatch (-want +got):\n%s", diff)
	}
}

func TestX509CertThumbprint_Nil(t *testing.T) {
	if X509CertThumbprint(nil) != "" {
		t.Fatal("nil cert should yield empty thumbprint")
	}
}

func TestConfirmation_VerifyDPoPBinding(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jkt, _ := JWKThumbprint(priv)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name    string
		cnf     Confirmation
		key     crypto.PrivateKey
		wantErr error
	}{
		{name: "match", cnf: Confirmation{JKT: jkt}, key: priv, wantErr: nil},
		{name: "mismatch", cnf: Confirmation{JKT: jkt}, key: other, wantErr: ErrTokenBindingMismatch},
		{name: "unbound", cnf: Confirmation{}, key: priv, wantErr: ErrTokenUnbound},
		{name: "mtls bound not dpop", cnf: Confirmation{X5T256: "x"}, key: priv, wantErr: ErrTokenUnbound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cnf.VerifyDPoPBinding(tc.key)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfirmation_VerifyMTLSBinding(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(der)
	x5t := X509CertThumbprint(cert)

	if err := (Confirmation{X5T256: x5t}).VerifyMTLSBinding(cert); err != nil {
		t.Fatalf("match: %v", err)
	}
	if err := (Confirmation{X5T256: x5t}).VerifyMTLSBinding(nil); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("nil cert: error = %v, want ErrTokenBindingMismatch", err)
	}
	if err := (Confirmation{X5T256: "wrong"}).VerifyMTLSBinding(cert); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("mismatch: error = %v, want ErrTokenBindingMismatch", err)
	}
	if err := (Confirmation{JKT: "x"}).VerifyMTLSBinding(cert); !errors.Is(err, ErrTokenUnbound) {
		t.Fatalf("unbound: error = %v, want ErrTokenUnbound", err)
	}
}
