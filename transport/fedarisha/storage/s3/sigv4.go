package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

// AWS Signature Version 4 for S3, hand-rolled.
//
// The AWS SDK would add 10-15 MB to the binary, which does not fit the router
// this client is built for. S3 needs a small enough slice of SigV4 that the
// signer below covers everything fedarisha does: six request shapes, all with
// a fully buffered payload, so the streaming/chunked variants are out of scope.

const (
	algorithm   = "AWS4-HMAC-SHA256"
	serviceName = "s3"
	iso8601     = "20060102T150405Z"
	yyyymmdd    = "20060102"

	// Payload hash of an empty body, precomputed — every GET/DELETE/HEAD sends it.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// uriEncode percent-encodes per RFC 3986 as S3 expects. Object keys keep their
// slashes as path separators; query components do not.
func uriEncode(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			b.WriteString("%")
			b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

// sign attaches the Authorization header. payloadHash must be the hex SHA-256
// of the exact bytes being sent; callers with no body pass emptyPayloadHash.
//
// Only host, x-amz-date and x-amz-content-sha256 are signed. Signing the
// minimum set keeps this robust against proxies that add or reorder headers —
// anything signed but rewritten in flight would fail verification at the peer.
func sign(req *http.Request, accessKey, secretKey, region, payloadHash string, now time.Time) {
	amzDate := now.UTC().Format(iso8601)
	dateStamp := now.UTC().Format(yyyymmdd)

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	canonicalHeaders := "host:" + host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	// S3 is the one service that does NOT re-encode the path when building the
	// canonical request: the canonical URI must be exactly the escaped path that
	// goes out on the wire. Running the path through uriEncode here instead
	// turns an already-escaped "%20" into "%2520" and a literal "+" into "%2B",
	// and the signature stops matching for any key outside [A-Za-z0-9-._~/].
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery(req),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, serviceName, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, serviceName)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("Authorization", algorithm+
		" Credential="+accessKey+"/"+scope+
		", SignedHeaders="+signedHeaders+
		", Signature="+signature)
}

// canonicalQuery renders the query string sorted by encoded key, as SigV4
// requires. net/url's Encode() sorts by raw key and uses form escaping, which
// differs from the S3 rules for characters like '+' and '*'.
func canonicalQuery(req *http.Request) string {
	values := req.URL.Query()
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, uriEncode(k, false))
	}
	sortStrings(keys)

	parts := make([]string, 0, len(keys))
	for _, encKey := range keys {
		for k, vs := range values {
			if uriEncode(k, false) != encKey {
				continue
			}
			for _, v := range vs {
				parts = append(parts, encKey+"="+uriEncode(v, false))
			}
		}
	}
	return strings.Join(parts, "&")
}

// sortStrings is an insertion sort — the query maps here hold at most a handful
// of keys, and this avoids pulling in sort for the router build.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
