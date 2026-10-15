package notarize

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

func newTestTSA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed rsa keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-tsa"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed parse cert: %v", err)
	}
	return cert, key
}

func mintToken(t *testing.T, cert *x509.Certificate, signer crypto.Signer, payload []byte, nonce *big.Int, addCert bool) []byte {
	t.Helper()
	sum := sha256.Sum256(payload)
	var certs []*x509.Certificate
	if addCert {
		certs = []*x509.Certificate{cert}
	}
	ts := timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     sum[:],
		Time:              time.Now().UTC(),
		SerialNumber:      big.NewInt(42),
		Policy:            []int{1, 2, 3},
		Nonce:             nonce,
		Certificates:      certs,
		AddTSACertificate: addCert,
	}
	resp, err := ts.CreateResponseWithOpts(cert, signer, crypto.SHA256)
	if err != nil {
		t.Fatalf("failed create response: %v", err)
	}
	return resp
}

func TestHTTPTimestamper_Success(t *testing.T) {
	cert, signer := newTestTSA(t)
	payload := []byte("canonical-gitproof-payload")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(mintToken(t, cert, signer, payload, req.Nonce, true))
	}))
	defer srv.Close()

	client := New(Config{URL: srv.URL, Authority: "Test DigiCert"})
	res, err := client.Timestamp(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected timestamp error: %v", err)
	}

	if res.Authority != "Test DigiCert" {
		t.Errorf("expected authority Test DigiCert, got %s", res.Authority)
	}
	if len(res.RawTokenDER) == 0 {
		t.Errorf("expected non-empty DER bytes")
	}

	// Verify using Verify function
	signingTime, err := Verify(res.RawTokenDER, payload)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if signingTime.IsZero() {
		t.Errorf("expected non-zero signing time")
	}

	// Verify digest mismatch fails
	_, err = Verify(res.RawTokenDER, []byte("tampered-payload"))
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("expected ErrDigestMismatch, got %v", err)
	}
}

func TestHTTPTimestamper_NonceMismatch(t *testing.T) {
	cert, signer := newTestTSA(t)
	payload := []byte("payload")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrongNonce := big.NewInt(9999999)
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(mintToken(t, cert, signer, payload, wrongNonce, true))
	}))
	defer srv.Close()

	client := New(Config{URL: srv.URL})
	_, err := client.Timestamp(context.Background(), payload)
	if !errors.Is(err, ErrNonceMismatch) {
		t.Errorf("expected ErrNonceMismatch, got %v", err)
	}
}

func TestHTTPTimestamper_NoSignerCertificate(t *testing.T) {
	cert, signer := newTestTSA(t)
	payload := []byte("payload")

	token := mintToken(t, cert, signer, payload, nil, false)
	_, err := ParseVerified(token, payload)
	if !errors.Is(err, ErrNoSignerCertificate) {
		t.Errorf("expected ErrNoSignerCertificate, got %v", err)
	}
}

func TestMockTimestamper(t *testing.T) {
	ctx := context.Background()
	mock := &MockTimestamper{
		FixedTime: time.Date(2026, 10, 14, 21, 30, 0, 0, time.UTC),
		Authority: "Custom Authority",
	}

	res, err := mock.Timestamp(ctx, []byte("hello world"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Authority != "Custom Authority" {
		t.Errorf("expected Custom Authority, got %s", res.Authority)
	}
	if res.Time.Unix() != 1792013400 {
		t.Errorf("expected timestamp 1792013400, got %d", res.Time.Unix())
	}

	// Test empty payload
	_, err = mock.Timestamp(ctx, nil)
	if !errors.Is(err, ErrEmptyPayload) {
		t.Errorf("expected ErrEmptyPayload, got %v", err)
	}

	// Test configured error
	mockErr := errors.New("network failure")
	mock.Err = mockErr
	_, err = mock.Timestamp(ctx, []byte("data"))
	if !errors.Is(err, mockErr) {
		t.Errorf("expected mockErr, got %v", err)
	}
}

func TestHTTPTimestamper_EmptyPayload(t *testing.T) {
	client := New(Config{URL: "http://example.com"})
	_, err := client.Timestamp(context.Background(), nil)
	if !errors.Is(err, ErrEmptyPayload) {
		t.Errorf("expected ErrEmptyPayload, got %v", err)
	}
}

func TestHTTPTimestamper_HttpErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	client := New(Config{
		URL:     server.URL,
		Timeout: 2 * time.Second,
	})

	_, err := client.Timestamp(context.Background(), []byte("payload"))
	if !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("expected ErrInvalidStatus, got %v", err)
	}
}

func TestHTTPTimestamper_InvalidResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not-a-valid-tsa-response"))
	}))
	defer server.Close()

	client := New(Config{URL: server.URL})
	_, err := client.Timestamp(context.Background(), []byte("payload"))
	if err == nil {
		t.Fatalf("expected error on invalid TSA response")
	}
}

func TestHTTPTimestamper_ConnectionFailure(t *testing.T) {
	client := New(Config{
		URL:     "http://127.0.0.1:54321/not-listening",
		Timeout: 100 * time.Millisecond,
	})
	_, err := client.Timestamp(context.Background(), []byte("payload"))
	if err == nil {
		t.Fatalf("expected network failure")
	}
}

func TestParseVerified_InvalidToken(t *testing.T) {
	_, err := ParseVerified([]byte("invalid_der"), []byte("payload"))
	if err == nil {
		t.Errorf("expected error for invalid token")
	}

	_, err = Verify([]byte("invalid_der"), []byte("payload"))
	if err == nil {
		t.Errorf("expected error for invalid token in Verify")
	}
}
