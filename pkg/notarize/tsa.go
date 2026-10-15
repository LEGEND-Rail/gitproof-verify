package notarize

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"
)

var (
	ErrEmptyPayload        = errors.New("notarize: cannot timestamp empty payload")
	ErrInvalidStatus       = errors.New("notarize: invalid HTTP status from TSA server")
	ErrDigestMismatch      = errors.New("notarize: token does not match payload digest")
	ErrNoSignerCertificate = errors.New("notarize: token carries no signer certificate")
	ErrNonceMismatch       = errors.New("notarize: token nonce does not match request")
)

// TimestampResult contains the RFC 3161 timestamp response.
type TimestampResult struct {
	RawTokenDER []byte
	Base64Token string
	Time        time.Time
	Authority   string
}

// Timestamper obtains an RFC 3161 timestamp over SHA-256(payload).
type Timestamper interface {
	Timestamp(ctx context.Context, payload []byte) (*TimestampResult, error)
}

// Config configures the HTTP RFC 3161 client.
type Config struct {
	URL       string
	Authority string
	Timeout   time.Duration
	Client    *http.Client
}

type httpTimestamper struct {
	url       string
	authority string
	client    *http.Client
}

// New returns an HTTP Timestamper configured for the specified TSA endpoint.
func New(cfg Config) Timestamper {
	client := cfg.Client
	if client == nil {
		to := cfg.Timeout
		if to == 0 {
			to = 10 * time.Second
		}
		client = &http.Client{Timeout: to}
	}
	auth := cfg.Authority
	if auth == "" {
		auth = cfg.URL
	}
	return &httpTimestamper{
		url:       cfg.URL,
		authority: auth,
		client:    client,
	}
}

// Timestamp requests an RFC 3161 timestamp token over the provided payload.
func (h *httpTimestamper) Timestamp(ctx context.Context, payload []byte) (*TimestampResult, error) {
	if len(payload) == 0 {
		return nil, ErrEmptyPayload
	}

	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("notarize: nonce generation failed: %w", err)
	}

	reqBytes, err := timestamp.CreateRequest(bytes.NewReader(payload), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
		Nonce:        nonce,
	})
	if err != nil {
		return nil, fmt.Errorf("notarize: failed to create timestamp request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("notarize: failed to build HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("notarize: TSA request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrInvalidStatus, resp.StatusCode)
	}

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("notarize: failed to read TSA response: %w", err)
	}

	ts, err := ParseVerified(respBytes, payload)
	if err != nil {
		return nil, fmt.Errorf("notarize: response verification failed: %w", err)
	}

	if ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		return nil, fmt.Errorf("notarize: %w", ErrNonceMismatch)
	}

	return &TimestampResult{
		RawTokenDER: respBytes,
		Base64Token: base64.StdEncoding.EncodeToString(respBytes),
		Time:        ts.Time.UTC(),
		Authority:   h.authority,
	}, nil
}

// ParseVerified parses a raw RFC 3161 response, checks the signature against the embedded certificate,
// and confirms that the message imprint matches SHA-256(payload).
func ParseVerified(token, payload []byte) (*timestamp.Timestamp, error) {
	ts, err := timestamp.ParseResponse(token)
	if err != nil {
		return nil, fmt.Errorf("notarize: parse token: %w", err)
	}
	if len(ts.Certificates) == 0 {
		return nil, ErrNoSignerCertificate
	}
	sum := sha256.Sum256(payload)
	if !bytes.Equal(ts.HashedMessage, sum[:]) {
		return nil, ErrDigestMismatch
	}
	return ts, nil
}

// Verify validates a retained RFC 3161 token against the original payload bytes.
func Verify(token, payload []byte) (time.Time, error) {
	ts, err := ParseVerified(token, payload)
	if err != nil {
		return time.Time{}, err
	}
	return ts.Time.UTC(), nil
}

// VerifyTSAAtGenTime validates the embedded TSA signer certificate chain
// against the exact second the RFC 3161 token was minted (point-in-time LTV),
// preventing false failures 5-10 years later when the TSA leaf cert expires.
func VerifyTSAAtGenTime(signerCert *x509.Certificate, intermediates []*x509.Certificate, roots *x509.CertPool, genTime time.Time) error {
	interPool := x509.NewCertPool()
	for _, ic := range intermediates {
		interPool.AddCert(ic)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: interPool,
		CurrentTime:   genTime.UTC(), // Critical: verify validity at time of signing, not time.Now()
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}

	if _, err := signerCert.Verify(opts); err != nil {
		return fmt.Errorf("TSA certificate chain invalid at genTime (%s): %w", genTime.UTC().Format(time.RFC3339), err)
	}
	return nil
}

// MockTimestamper provides deterministic responses for offline tests.
type MockTimestamper struct {
	FixedTime time.Time
	Authority string
	Err       error
}

func (m *MockTimestamper) Timestamp(_ context.Context, payload []byte) (*TimestampResult, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if len(payload) == 0 {
		return nil, ErrEmptyPayload
	}
	t := m.FixedTime
	if t.IsZero() {
		t = time.Date(2026, 10, 14, 21, 30, 0, 0, time.UTC)
	}
	auth := m.Authority
	if auth == "" {
		auth = "Mock TSA Authority"
	}
	dummyDER := []byte("MOCK_RFC3161_TST_DER_BYTES")
	return &TimestampResult{
		RawTokenDER: dummyDER,
		Base64Token: base64.StdEncoding.EncodeToString(dummyDER),
		Time:        t,
		Authority:   auth,
	}, nil
}
