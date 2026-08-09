// Package s3 implements the Storage interface for S3-compatible object stores.
// Works with AWS S3, MinIO, Backblaze B2, Cloudflare R2, Selectel, VK Cloud, etc.
//
// This is a hand-rolled client rather than the AWS SDK: the SDK costs 10-15 MB
// of binary, and the Keenetic this is built for has ~46 MB free. Only the six
// operations fedarisha actually performs are implemented.
package s3

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/mihomo/transport/fedarisha/storage"
)

// Config holds S3 connection parameters.
type Config struct {
	Bucket    string // S3 bucket name
	Prefix    string // Key prefix (e.g. "fedarisha/")
	Region    string // AWS region (default "us-east-1")
	Endpoint  string // Custom endpoint for S3-compatible services (MinIO, R2, etc.)
	AccessKey string
	SecretKey string

	// DialContext, when set, replaces the standard dialer for every request to
	// the bucket. Inside mihomo this must be supplied: the process installs a
	// guard that terminates it if anything reaches net.DefaultResolver, so a
	// stock net/http client dies on the first DNS lookup. It also keeps this
	// traffic on the direct path rather than looping back through a proxy.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// S3Store implements storage.Storage for S3-compatible backends.
//
// Reads and writes use SEPARATE http.Clients with independent connection
// pools. This is deliberate: fedarisha multiplexes a bidirectional stream over
// S3, and a heavy read flood (GET-ing the peer's data files, plus DELETE-ing
// consumed ones) must never exhaust the connection pool that the write path
// (PUT-ing window-update / data files) depends on. When they shared one pool, a
// sustained download saturated it, starved the window-update PUTs, and the
// peer's yamux send window filled and the whole channel wedged. Splitting the
// pools guarantees the write direction always has connections of its own.
type S3Store struct {
	cfg         Config
	readClient  *http.Client // GET, List, Delete, HeadBucket (read/cleanup path)
	writeClient *http.Client // PutObject only (the latency-critical write path)

	baseURL   string // scheme://host[/bucket] with no trailing slash
	pathStyle bool
}

// newHTTPClient builds an HTTP client with a private connection pool sized to
// maxConns. Per-op context timeouts (read/upload) are the real deadline, so
// ResponseHeaderTimeout is only a backstop.
func newHTTPClient(maxConns int, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	if dial == nil {
		dial = (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:          maxConns,
			MaxIdleConnsPerHost:   maxConns,
			MaxConnsPerHost:       maxConns,
			IdleConnTimeout:       120 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			DialContext:           dial,
		},
	}
}

// New creates a new S3 storage backend.
func New(cfg Config) *S3Store {
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.Prefix != "" && !strings.HasSuffix(cfg.Prefix, "/") {
		cfg.Prefix += "/"
	}

	s := &S3Store{
		cfg: cfg,
		// Read pool covers concurrent GETs (read-ahead window x hedge) and the
		// DELETEs of consumed files; write pool is dedicated to the PUT workers.
		readClient:  newHTTPClient(96, cfg.DialContext),
		writeClient: newHTTPClient(48, cfg.DialContext),
	}

	if cfg.Endpoint != "" {
		// Custom endpoints get path-style addressing: S3-compatible providers
		// rarely wire up per-bucket virtual hosts, and a bucket name with dots
		// breaks TLS verification under the virtual-host form anyway.
		ep := strings.TrimSuffix(cfg.Endpoint, "/")
		if !strings.Contains(ep, "://") {
			ep = "https://" + ep
		}
		s.baseURL = ep + "/" + cfg.Bucket
		s.pathStyle = true
	} else {
		s.baseURL = "https://" + cfg.Bucket + ".s3." + cfg.Region + ".amazonaws.com"
	}

	return s
}

func (s *S3Store) key(path string) string {
	path = strings.TrimPrefix(path, "/")
	return s.cfg.Prefix + path
}

// objectURL builds the request URL for an object key.
func (s *S3Store) objectURL(key string) string {
	return s.baseURL + "/" + strings.TrimPrefix(key, "/")
}

// do signs and executes a request, returning the body on 2xx.
func (s *S3Store) do(ctx context.Context, client *http.Client, method, rawURL string, body []byte, query url.Values) ([]byte, error) {
	if query != nil && len(query) > 0 {
		rawURL += "?" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}

	payloadHash := emptyPayloadHash
	if body != nil {
		payloadHash = sha256Hex(body)
	}
	sign(req, s.cfg.AccessKey, s.cfg.SecretKey, s.cfg.Region, payloadHash, time.Now())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &Error{StatusCode: resp.StatusCode, Body: string(data), Method: method, URL: rawURL}
	}
	return data, nil
}

// Error reports a non-2xx S3 response. The body carries the provider's XML
// error document, which is what actually names the problem (SignatureDoesNotMatch,
// NoSuchKey, AccessDenied...), so it is preserved verbatim.
type Error struct {
	StatusCode int
	Body       string
	Method     string
	URL        string
}

func (e *Error) Error() string {
	body := e.Body
	if len(body) > 400 {
		body = body[:400] + "..."
	}
	return fmt.Sprintf("s3: %s %s: HTTP %d: %s", e.Method, e.URL, e.StatusCode, body)
}

// NotFound reports whether the error is a 404, which the transport treats as
// "not written yet" rather than as a failure while polling for peer files.
func NotFound(err error) bool {
	var e *Error
	if ok := asError(err, &e); ok {
		return e.StatusCode == http.StatusNotFound
	}
	return false
}

func asError(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ---------- storage.Storage ----------

func (s *S3Store) Init(ctx context.Context) error {
	// Verify access by doing a HeadBucket.
	_, err := s.do(ctx, s.readClient, http.MethodHead, s.baseURL, nil, nil)
	return err
}

func (s *S3Store) EnsureDir(_ context.Context, _ string) error {
	// S3 has no directories — they're implicit from key prefixes.
	return nil
}

func (s *S3Store) Upload(ctx context.Context, path string, data []byte) error {
	_, err := s.do(ctx, s.writeClient, http.MethodPut, s.objectURL(s.key(path)), data, nil)
	return err
}

func (s *S3Store) Download(ctx context.Context, path string) ([]byte, error) {
	return s.do(ctx, s.readClient, http.MethodGet, s.objectURL(s.key(path)), nil, nil)
}

// listBucketResult mirrors the ListObjectsV2 XML response.
type listBucketResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		LastModified time.Time `xml:"LastModified"`
	} `xml:"Contents"`
	CommonPrefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
}

func (s *S3Store) List(ctx context.Context, dir string, prefix string) ([]storage.FileInfo, error) {
	dirKey := s.key(dir)
	if !strings.HasSuffix(dirKey, "/") {
		dirKey += "/"
	}

	searchPrefix := dirKey
	if prefix != "" {
		searchPrefix = dirKey + prefix
	}

	var result []storage.FileInfo
	var token string
	for {
		q := url.Values{}
		q.Set("list-type", "2")
		q.Set("prefix", searchPrefix)
		q.Set("delimiter", "/")
		if token != "" {
			q.Set("continuation-token", token)
		}

		data, err := s.do(ctx, s.readClient, http.MethodGet, s.baseURL, nil, q)
		if err != nil {
			return nil, err
		}

		var out listBucketResult
		if err := xml.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("s3: parse list response: %w", err)
		}

		for _, obj := range out.Contents {
			name := strings.TrimPrefix(obj.Key, dirKey)
			if name == "" {
				continue
			}
			result = append(result, storage.FileInfo{
				Name:     name,
				Path:     obj.Key,
				Size:     obj.Size,
				Modified: obj.LastModified,
				Created:  obj.LastModified,
				IsDir:    false,
			})
		}

		for _, cp := range out.CommonPrefixes {
			name := strings.TrimPrefix(cp.Prefix, dirKey)
			name = strings.TrimSuffix(name, "/")
			if name == "" {
				continue
			}
			result = append(result, storage.FileInfo{
				Name:  name,
				Path:  cp.Prefix,
				IsDir: true,
			})
		}

		if !out.IsTruncated || out.NextContinuationToken == "" {
			break
		}
		token = out.NextContinuationToken
	}

	return result, nil
}

func (s *S3Store) Delete(ctx context.Context, path string) error {
	_, err := s.do(ctx, s.readClient, http.MethodDelete, s.objectURL(s.key(path)), nil, nil)
	return err
}

func (s *S3Store) Watch(ctx context.Context, dir string, since time.Time, timeout time.Duration) ([]storage.FileInfo, error) {
	// S3 has no push notifications — fall back to polling.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		files, err := s.List(ctx, dir, "")
		if err != nil {
			return nil, err
		}
		var newer []storage.FileInfo
		for _, f := range files {
			if f.Modified.After(since) {
				newer = append(newer, f)
			}
		}
		if len(newer) > 0 {
			return newer, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil, nil
}

// deleteRequest is the POST ?delete payload.
type deleteRequest struct {
	XMLName xml.Name           `xml:"Delete"`
	Quiet   bool               `xml:"Quiet"`
	Objects []deleteObjectItem `xml:"Object"`
}

type deleteObjectItem struct {
	Key string `xml:"Key"`
}

// BatchDelete removes multiple objects in one API call (up to 1000).
func (s *S3Store) BatchDelete(ctx context.Context, paths []string) error {
	if len(paths) == 0 {
		return nil
	}

	payload := deleteRequest{Quiet: true}
	for _, p := range paths {
		payload.Objects = append(payload.Objects, deleteObjectItem{Key: s.key(p)})
	}
	body, err := xml.Marshal(payload)
	if err != nil {
		return err
	}

	rawURL := s.baseURL + "?delete="
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(body))
	// DeleteObjects is the one call that mandates Content-MD5; providers reject
	// it outright without one. It is not part of the signed header set, so it
	// has to be attached before signing only in the sense of being sent — the
	// signature covers the payload hash, which already binds the body.
	sum := md5.Sum(body)
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	req.Header.Set("Content-Type", "application/xml")

	sign(req, s.cfg.AccessKey, s.cfg.SecretKey, s.cfg.Region, sha256Hex(body), time.Now())

	resp, err := s.readClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{StatusCode: resp.StatusCode, Body: string(data), Method: http.MethodPost, URL: rawURL}
	}
	return nil
}
