package main

// Differential test for the hand-rolled SigV4 signer.
//
// The signer in the mihomo fork was written from the spec without a bucket to
// try it against, so it is checked here against the AWS SDK's own signer: the
// same requests are signed both ways and the Authorization headers compared
// byte for byte. Any disagreement in canonicalisation, encoding or the signing
// key chain shows up as a mismatched signature.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	accessKey = "AKIAIOSFODNN7EXAMPLE"
	secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	region    = "ru-central1"
)

var fixedTime = time.Date(2026, 8, 9, 12, 34, 56, 0, time.UTC)

type testCase struct {
	name   string
	method string
	url    string
	body   []byte
}

func main() {
	cases := []testCase{
		{
			name:   "HeadBucket",
			method: http.MethodHead,
			url:    "https://s3.example-cloud.ru/my-bucket",
		},
		{
			name:   "GetObject",
			method: http.MethodGet,
			url:    "https://s3.example-cloud.ru/my-bucket/fedarisha/sessions/abc123/c_00000042",
		},
		{
			name:   "PutObject with body",
			method: http.MethodPut,
			url:    "https://s3.example-cloud.ru/my-bucket/fedarisha/sessions/abc123/s_00000001",
			body:   []byte("some binary-ish payload \x00\x01\x02 with bytes"),
		},
		{
			name:   "ListObjectsV2 with query",
			method: http.MethodGet,
			url:    "https://s3.example-cloud.ru/my-bucket?continuation-token=1%2FabC%3D%3D&delimiter=%2F&list-type=2&prefix=fedarisha%2Fsessions%2Fabc123%2F",
		},
		{
			name:   "DeleteObjects batch",
			method: http.MethodPost,
			url:    "https://s3.example-cloud.ru/my-bucket?delete=",
			body:   []byte(`<Delete><Quiet>true</Quiet><Object><Key>fedarisha/x</Key></Object></Delete>`),
		},
		{
			name:   "Key with characters that must be escaped",
			method: http.MethodGet,
			url:    "https://s3.example-cloud.ru/my-bucket/fedarisha/a+b/c%20d/e~f.g",
		},
		{
			name:   "Virtual-host style endpoint",
			method: http.MethodGet,
			url:    "https://my-bucket.s3.us-east-1.amazonaws.com/fedarisha/sessions/x/hello",
		},
	}

	failed := 0
	for _, tc := range cases {
		mine, theirs, err := signBoth(tc)
		if err != nil {
			fmt.Printf("ERROR %-42s %v\n", tc.name, err)
			failed++
			continue
		}
		if mine == theirs {
			fmt.Printf("OK    %s\n", tc.name)
			continue
		}
		failed++
		fmt.Printf("FAIL  %s\n", tc.name)
		fmt.Printf("   mine:   %s\n", mine)
		fmt.Printf("   aws:    %s\n", theirs)
	}

	fmt.Printf("\n%d/%d matched\n", len(cases)-failed, len(cases))
	if failed > 0 {
		os.Exit(1)
	}
}

func signBoth(tc testCase) (mine, theirs string, err error) {
	payloadHash := emptyPayloadHash
	if tc.body != nil {
		sum := sha256.Sum256(tc.body)
		payloadHash = hex.EncodeToString(sum[:])
	}

	// --- signer under test ---
	reqA, err := newRequest(tc)
	if err != nil {
		return "", "", err
	}
	sign(reqA, accessKey, secretKey, region, payloadHash, fixedTime)
	mine = reqA.Header.Get("Authorization")

	// --- reference implementation ---
	reqB, err := newRequest(tc)
	if err != nil {
		return "", "", err
	}
	// Match the header set the signer under test signs: host is implicit,
	// x-amz-date is set by the SDK signer itself, so only the payload hash
	// header has to be present up front.
	reqB.Header.Set("X-Amz-Content-Sha256", payloadHash)
	// The SDK signs content-length whenever it is known; the signer under test
	// deliberately does not, which is valid — SignedHeaders declares the set the
	// server verifies against. Zeroing it here keeps both sides on the same
	// header set so the comparison isolates the canonicalisation and the HMAC
	// chain rather than re-testing that policy choice.
	reqB.ContentLength = 0

	creds := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	// SignHTTP defaults to re-escaping the path, which is correct for most AWS
	// services and wrong for S3. The S3 client sets this option internally; a
	// direct SignHTTP call has to opt in, or the reference disagrees with every
	// real S3 endpoint on any key containing an escapable character.
	signer := v4.NewSigner(func(o *v4.SignerOptions) {
		o.DisableURIPathEscaping = true
	})
	if err := signer.SignHTTP(context.Background(), creds, reqB, payloadHash, "s3", region, fixedTime); err != nil {
		return "", "", err
	}
	theirs = reqB.Header.Get("Authorization")

	return mine, theirs, nil
}

func newRequest(tc testCase) (*http.Request, error) {
	var body *bytes.Reader
	if tc.body != nil {
		body = bytes.NewReader(tc.body)
		req, err := http.NewRequest(tc.method, tc.url, body)
		if err != nil {
			return nil, err
		}
		req.ContentLength = int64(len(tc.body))
		return req, nil
	}
	return http.NewRequest(tc.method, tc.url, nil)
}
