# SigV4 differential check

The S3 signer in `transport/fedarisha/storage/s3` is hand-rolled to keep the
AWS SDK (and 10-15 MB of binary) off the router build. This checks it against
the SDK's own signer: the same requests are signed both ways and the
`Authorization` headers compared byte for byte, so any disagreement in
canonicalisation, URI escaping or the signing-key chain fails the run.

It lives in a `_`-prefixed directory and its own module, so the Go tool ignores
it — the AWS dependency never reaches the mihomo build.

    ./_sigv4check/run.sh

Two things this caught, both of which look identical to "it just returns 403":

- The canonical URI must be the escaped path exactly as sent. S3 is the one
  service that does not re-escape it; running the path through a generic
  encoder breaks every key containing a character outside `[A-Za-z0-9-._~/]`.
- The reference itself has to be put in S3 mode (`DisableURIPathEscaping`).
  The S3 client sets it internally, so a direct `SignHTTP` call disagrees with
  every real S3 endpoint until it opts in.
