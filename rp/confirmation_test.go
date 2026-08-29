package rp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
		"jku":"https://example.com/jwks.json",
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
		JKU:    "https://example.com/jwks.json",
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

func TestJWKThumbprint_RSA_MatchesRFC7638Algorithm(t *testing.T) {
	// Independently compute the RFC 7638 canonical thumbprint: SHA-256 over
	// the minimal JSON {"e","kty","n"} with lexicographic member order and no
	// whitespace. This cross-checks JWKThumbprint (which delegates to go-jose)
	// against the RFC algorithm directly, without relying on any hardcoded
	// vector that could be mistyped.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	got, err := JWKThumbprint(priv)
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}

	nB64 := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	// 65537 == 0x010001, which base64url-encodes to "AQAB".
	canon := []byte(`{"e":"AQAB","kty":"RSA","n":"` + nB64 + `"}`)
	sum := sha256.Sum256(canon)
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("RSA thumbprint does not match RFC 7638 algorithm (-want +got):\n%s", diff)
	}
}

func TestJWKThumbprint_EC_MatchesRFC7638Algorithm(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	got, err := JWKThumbprint(priv)
	if err != nil {
		t.Fatalf("JWKThumbprint: %v", err)
	}

	// RFC 7638 §3.2: EC coordinates are fixed-length field elements padded to
	// the curve byte size, then base64url-encoded.
	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	xB64 := base64.RawURLEncoding.EncodeToString(padFixed(priv.X.Bytes(), byteLen))
	yB64 := base64.RawURLEncoding.EncodeToString(padFixed(priv.Y.Bytes(), byteLen))
	canon := []byte(`{"crv":"P-256","kty":"EC","x":"` + xB64 + `","y":"` + yB64 + `"}`)
	sum := sha256.Sum256(canon)
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("EC thumbprint does not match RFC 7638 algorithm (-want +got):\n%s", diff)
	}
}

// padFixed left-pads b with zeros so its length is exactly size, matching the
// fixed-length octet encoding RFC 7638 requires for EC coordinates.
func padFixed(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func TestJWKThumbprint_UnsupportedKey(t *testing.T) {
	_, err := JWKThumbprint("not a key")
	if err == nil {
		t.Fatal("expected error for unsupported key")
	}
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("error should wrap ErrInvalidConfiguration, got %v", err)
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

func TestParseAccessTokenConfirmation(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"x","cnf":{"jkt":"abc"}}`))
	raw := header + "." + payload + "."
	got, err := ParseAccessTokenConfirmation(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := Confirmation{JKT: "abc"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestParseAccessTokenConfirmation_X5T256(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"x","cnf":{"x5t#S256":"cert-thumb"}}`))
	raw := header + "." + payload + ".sig"
	got, err := ParseAccessTokenConfirmation(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := Confirmation{X5T256: "cert-thumb"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestParseAccessTokenConfirmation_Errors(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		if _, err := ParseAccessTokenConfirmation("not-a-jwt"); err == nil {
			t.Fatal("expected error for malformed JWT")
		}
	})
	t.Run("two parts", func(t *testing.T) {
		if _, err := ParseAccessTokenConfirmation("a.b"); err == nil {
			t.Fatal("expected error for two-part input")
		}
	})
	t.Run("no cnf returns ErrTokenUnbound", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`))
		raw := header + "." + payload + "."
		_, err := ParseAccessTokenConfirmation(raw)
		if err == nil {
			t.Fatal("expected error for token without cnf")
		}
		if !errors.Is(err, ErrTokenUnbound) {
			t.Fatalf("error = %v, want ErrTokenUnbound", err)
		}
	})
	t.Run("invalid base64 payload", func(t *testing.T) {
		raw := "eyJhbGciOiJub25lIn0" + "." + "!!!not-base64!!!" + "."
		if _, err := ParseAccessTokenConfirmation(raw); err == nil {
			t.Fatal("expected error for invalid base64 payload")
		}
	})
}
