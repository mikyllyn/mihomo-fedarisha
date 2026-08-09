#!/bin/sh
# Refresh the copy of the signer under test, then run the comparison.
# Copying rather than importing is forced by `sign` being unexported; doing it
# here means the check can never quietly test a stale copy.
set -eu
cd "$(dirname "$0")"
cp ../transport/fedarisha/storage/s3/sigv4.go ./sigv4.go
sed -i 's|^package s3$|package main|' ./sigv4.go
go run .
