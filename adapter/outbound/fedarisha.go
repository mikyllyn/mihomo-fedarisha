package outbound

import (
	"context"
	"errors"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/fedarisha"
)

// Fedarisha proxies over an S3 bucket instead of a network endpoint: both sides
// exchange small objects in a shared prefix, and yamux multiplexes connections
// over that. There is no server host or port — the bucket is the rendezvous.
type Fedarisha struct {
	*Base
	client *fedarisha.Client
	option *FedarishaOption
}

// FedarishaStorageOption carries the object-store credentials the panel issues
// per user. Field names mirror the xray-json shape the panel already emits, so
// the two generators stay a thin transform of each other.
type FedarishaStorageOption struct {
	Type        string `proxy:"type,omitempty"`
	Bucket      string `proxy:"bucket"`
	Prefix      string `proxy:"prefix,omitempty"`
	Region      string `proxy:"region,omitempty"`
	Endpoint    string `proxy:"endpoint,omitempty"`
	AccessKey   string `proxy:"access-key"`
	SecretKey   string `proxy:"secret-key"`
	SessionsDir string `proxy:"sessions-dir,omitempty"`
}

// FedarishaTuningOption is optional; zero values keep the transport defaults.
type FedarishaTuningOption struct {
	PollIntervalMs   int `proxy:"poll-interval-ms,omitempty"`
	WriteIntervalMs  int `proxy:"write-interval-ms,omitempty"`
	IdleTimeoutSec   int `proxy:"idle-timeout-sec,omitempty"`
	MaxFileSizeBytes int `proxy:"max-file-size-bytes,omitempty"`
}

type FedarishaOption struct {
	BasicOption
	Name    string                 `proxy:"name"`
	Storage FedarishaStorageOption `proxy:"storage"`
	Tuning  FedarishaTuningOption  `proxy:"tuning,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (f *Fedarisha) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	stream, err := f.client.OpenStream(ctx)
	if err != nil {
		return nil, err
	}

	host := metadata.String()
	if err := fedarisha.WriteTargetHeader(stream, host, metadata.DstPort, false); err != nil {
		stream.Close()
		return nil, err
	}

	return NewConn(stream, f), nil
}

// ListenPacketContext implements C.ProxyAdapter.
//
// UDP is not wired up yet. The server expects fedarisha's own packet framing
// rather than mihomo's UDP-over-TCP, so it needs the packet reader/writer pair
// ported alongside this adapter; refusing here is better than silently handing
// back a connection that the peer would misparse as a TCP stream.
func (f *Fedarisha) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("fedarisha: UDP is not supported yet")
}

// SupportUOT implements C.ProxyAdapter
func (f *Fedarisha) SupportUOT() bool {
	return false
}

// ProxyInfo implements C.ProxyAdapter
func (f *Fedarisha) ProxyInfo() C.ProxyInfo {
	info := f.Base.ProxyInfo()
	info.DialerProxy = f.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (f *Fedarisha) Close() error {
	if f.client != nil {
		return f.client.Close()
	}
	return nil
}

func NewFedarisha(option FedarishaOption) (*Fedarisha, error) {
	if option.Storage.Bucket == "" {
		return nil, errors.New("fedarisha: storage.bucket is required")
	}
	if option.Storage.AccessKey == "" || option.Storage.SecretKey == "" {
		return nil, errors.New("fedarisha: storage credentials are required")
	}

	// Addr is display-only here: there is no endpoint to dial, and the health
	// check reaches its probe URL through the tunnel rather than by connecting
	// to this address. Naming the bucket makes the dashboard readable.
	addr := option.Storage.Bucket
	if option.Storage.Endpoint != "" {
		addr = strings.TrimPrefix(strings.TrimPrefix(option.Storage.Endpoint, "https://"), "http://") + "/" + option.Storage.Bucket
	}

	outbound := &Fedarisha{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Fedarisha,
			ProviderName: option.ProviderName,
			UDP:          false,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}

	// Constructing the client verifies bucket access, so a wrong key or endpoint
	// fails here with the provider's own error rather than on first use.
	client, err := fedarisha.NewClient(context.Background(),
		fedarisha.StorageConfig{
			Type:        option.Storage.Type,
			Bucket:      option.Storage.Bucket,
			Prefix:      option.Storage.Prefix,
			Region:      option.Storage.Region,
			Endpoint:    option.Storage.Endpoint,
			AccessKey:   option.Storage.AccessKey,
			SecretKey:   option.Storage.SecretKey,
			SessionsDir: option.Storage.SessionsDir,
		},
		fedarisha.TuningConfig{
			PollIntervalMs:   option.Tuning.PollIntervalMs,
			WriteIntervalMs:  option.Tuning.WriteIntervalMs,
			IdleTimeoutSec:   option.Tuning.IdleTimeoutSec,
			MaxFileSizeBytes: option.Tuning.MaxFileSizeBytes,
		})
	if err != nil {
		return nil, err
	}
	outbound.client = client

	return outbound, nil
}
