package fedarisha

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/fedarisha/storage"
	"github.com/metacubex/mihomo/transport/fedarisha/storage/s3"

	"github.com/metacubex/yamux"
)

// targetHeaderUDPFlag marks the destination in a stream header as UDP. It rides
// in the high bit of the host-length field, so a host may be at most 32767 bytes.
const targetHeaderUDPFlag uint16 = 0x8000

// StorageConfig describes the object store backing a fedarisha session.
type StorageConfig struct {
	Type        string
	Bucket      string
	Prefix      string
	Region      string
	Endpoint    string
	AccessKey   string
	SecretKey   string
	SessionsDir string

	// DialContext must be supplied by the caller inside mihomo — see the note on
	// s3.Config. Reaching the bucket with a stock dialer terminates the process.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// TuningConfig mirrors the optional tuning block the panel emits alongside the
// storage credentials. Zero values mean "leave the transport default alone".
type TuningConfig struct {
	PollIntervalMs   int
	WriteIntervalMs  int
	IdleTimeoutSec   int
	MaxFileSizeBytes int
}

// Client owns one yamux session multiplexed over an S3-backed connection, and
// hands out streams for individual proxied connections.
//
// A single S3 session is expensive to establish — it costs a directory create,
// a hello upload and a poll for the server's ACK, so seconds — which is why the
// session is shared across every connection and only re-dialled when it breaks.
type Client struct {
	dialer *Dialer

	mu       sync.Mutex
	session  *yamux.Session
	initDone bool
}

// NewClient builds a client from the storage and tuning blocks.
//
// Deliberately does no network I/O. mihomo parses a proxy provider as a unit:
// if any proxy's constructor returns an error the whole list is discarded, so
// verifying bucket access here would let one unreachable S3 endpoint take down
// every other proxy in the same subscription — including the ones that have
// nothing to do with fedarisha. Access is checked on first use instead, where
// the failure is contained to this proxy.
func NewClient(_ context.Context, sc StorageConfig, tuning TuningConfig) (*Client, error) {
	store, err := buildStorage(sc)
	if err != nil {
		return nil, err
	}

	sessionsDir := sc.SessionsDir
	if sessionsDir == "" {
		sessionsDir = "sessions"
	}

	d := &Dialer{Store: store, SessionsDir: sessionsDir}
	applyTuning(d, tuning)

	return &Client{dialer: d}, nil
}

// buildStorage constructs the backend without touching the network — see
// NewClient for why that matters.
func buildStorage(cfg StorageConfig) (storage.Storage, error) {
	storageType := strings.ToLower(cfg.Type)
	if storageType == "" && cfg.Bucket != "" {
		storageType = "s3"
	}

	switch storageType {
	case "s3":
		if cfg.Bucket == "" {
			return nil, fmt.Errorf("fedarisha: s3 bucket is empty")
		}
		return s3.New(s3.Config{
			Bucket:      cfg.Bucket,
			Prefix:      cfg.Prefix,
			Region:      cfg.Region,
			Endpoint:    cfg.Endpoint,
			AccessKey:   cfg.AccessKey,
			SecretKey:   cfg.SecretKey,
			DialContext: cfg.DialContext,
		}), nil
	default:
		return nil, fmt.Errorf("fedarisha: unsupported storage type %q", cfg.Type)
	}
}

func applyTuning(d *Dialer, t TuningConfig) {
	if t.PollIntervalMs > 0 {
		d.PollInterval = time.Duration(t.PollIntervalMs) * time.Millisecond
	}
	if t.WriteIntervalMs > 0 {
		d.WriteInterval = time.Duration(t.WriteIntervalMs) * time.Millisecond
	}
	if t.IdleTimeoutSec > 0 {
		d.IdleTimeout = time.Duration(t.IdleTimeoutSec) * time.Second
	}
	if t.MaxFileSizeBytes > 0 {
		d.MaxFileSize = t.MaxFileSizeBytes
	}
}

// yamuxSessionConfig relaxes the stock yamux timeouts, which assume a
// low-latency TCP carrier. This transport rides on S3 with ~50-900ms round
// trips and quiet pauses (a paused video sends nothing for seconds), so the
// default 60s timeouts kill healthy sessions mid-stream and tear down every
// multiplexed connection at once.
//
// Values are carried over from the Xray implementation deliberately — they were
// tuned against real S3 behaviour, and the reasoning is worth keeping:
//   - MaxStreamWindowSize 64MB: each window update is a full S3 round trip, so
//     throughput is roughly window / update-RTT; a small window throttles hard.
//   - Keepalive is the only liveness signal over a connectionless channel, and
//     doubles as the wedge detector — Conn.Write buffers rather than blocking,
//     so ConnectionWriteTimeout only ever gates the pong.
//
// Xray also pins StreamOpenTimeout to 0, because a slow stream-open ack was
// gracefully closing whole sessions. mihomo's yamux fork dropped that timeout
// entirely, so there is nothing to disable here.
func yamuxSessionConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard // mihomo has its own logger; yamux chatter is noise
	cfg.MaxStreamWindowSize = 64 * 1024 * 1024
	cfg.ConnectionWriteTimeout = 30 * time.Second
	cfg.KeepAliveInterval = 10 * time.Second
	return cfg
}

func (c *Client) getSession(ctx context.Context) (*yamux.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil && !c.session.IsClosed() {
		return c.session, nil
	}

	// Verify bucket access on first use rather than at construction. A failure
	// here fails this proxy's dial, which is what a health check will report —
	// instead of taking the whole provider down at parse time.
	//
	// Retried until it succeeds rather than remembered: the first attempt can
	// fail because the link is still coming up at boot, and caching that would
	// disable the proxy until the core restarts.
	if !c.initDone {
		if err := c.dialer.Store.Init(ctx); err != nil {
			return nil, fmt.Errorf("fedarisha: storage init: %w", err)
		}
		c.initDone = true
	}

	conn, err := c.dialer.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("fedarisha dial: %w", err)
	}

	// nil memory manager: the fork falls back to an unaccounted one, which is
	// what the upstream Xray implementation effectively uses.
	session, err := yamux.Client(conn, yamuxSessionConfig(), nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("fedarisha: yamux client: %w", err)
	}

	c.session = session
	return session, nil
}

// OpenStream returns a new multiplexed stream, re-dialling once if the cached
// session turns out to be dead. The retry matters: a session can be torn down
// between the liveness check and the Open, and without it every such race would
// surface to the user as a failed connection.
func (c *Client) OpenStream(ctx context.Context) (net.Conn, error) {
	session, err := c.getSession(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := session.Open(ctx)
	if err != nil {
		c.mu.Lock()
		if c.session == session {
			c.session.Close()
			c.session = nil
		}
		c.mu.Unlock()

		session, err = c.getSession(ctx)
		if err != nil {
			return nil, err
		}
		return session.Open(ctx)
	}
	return stream, nil
}

// Close tears down the shared session.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		err := c.session.Close()
		c.session = nil
		return err
	}
	return nil
}

// WriteTargetHeader announces the destination on a freshly opened stream:
// uint16 host length (high bit set for UDP), the host, then uint16 port.
func WriteTargetHeader(w io.Writer, host string, port uint16, udp bool) error {
	if host == "" {
		return fmt.Errorf("fedarisha: empty target host")
	}
	if len(host) > 32767 {
		return fmt.Errorf("fedarisha: target host is too long")
	}

	hostLen := uint16(len(host))
	if udp {
		hostLen |= targetHeaderUDPFlag
	}

	var header bytes.Buffer
	if err := binary.Write(&header, binary.BigEndian, hostLen); err != nil {
		return err
	}
	if _, err := header.WriteString(host); err != nil {
		return err
	}
	if err := binary.Write(&header, binary.BigEndian, port); err != nil {
		return err
	}
	_, err := w.Write(header.Bytes())
	return err
}
