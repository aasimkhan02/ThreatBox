package analysis

type Event struct {
	Type       string `json:"type"`
	Time       string `json:"time"`
	PID        uint64 `json:"pid,omitempty"`
	ThreadID   uint64 `json:"thread_id,omitempty"`
	PPID       uint64 `json:"ppid,omitempty"`
	Image      string `json:"image,omitempty"`
	Command    string `json:"command,omitempty"`
	FileName   string `json:"file_name,omitempty"`
	ParentPath string `json:"parent_path,omitempty"`
	FileObject uint64 `json:"file_object,omitempty"`
	FileKey    uint64 `json:"file_key,omitempty"`
	IoSize     uint64 `json:"io_size,omitempty"`
	LostEvents uint64 `json:"lost_events,omitempty"`

	// Network (TCP + UDP)
	SourceIP   string `json:"source_ip,omitempty"`
	SourcePort uint64 `json:"source_port,omitempty"`
	DestIP     string `json:"dest_ip,omitempty"`
	DestPort   uint64 `json:"dest_port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`

	// Registry
	RegistryKey    string `json:"registry_key,omitempty"`
	RegistryHandle uint64 `json:"registry_handle,omitempty"`

	// DNS
	DNSQueryName string   `json:"dns_query_name,omitempty"`
	DNSResults   []string `json:"dns_results,omitempty"`

	// Image / DLL load. The Image field above doubles as the loaded
	// module's path for image_load events, matching the collector's
	// JSON (it reuses "image" rather than adding a separate key).
	ImageBase     uint64 `json:"image_base,omitempty"`
	ImageSize     uint64 `json:"image_size,omitempty"`
	ImageChecksum uint64 `json:"image_checksum,omitempty"`
}

type ProcessNode struct {
	PID      uint64
	PPID     uint64
	Image    string
	Command  string
	Time     string
	Children []*ProcessNode
}

type FileActivity struct {
	Action string
	Path   string
	PID    uint64
	Image  string
	Count  int
	Bytes  uint64
}

// NetworkActivity is a sample-attributed, deduplicated view of TCP
// and UDP events (network_connect, network_accept, network_udp_send,
// network_udp_receive).
type NetworkActivity struct {
	Type       string
	Protocol   string
	PID        uint64
	Image      string
	SourceIP   string
	SourcePort uint64
	DestIP     string
	DestPort   uint64
	Count      int
}

// RegistryActivity is a sample-attributed, deduplicated view of
// registry create/open/set-value/delete-value/delete events.
type RegistryActivity struct {
	Action string
	Key    string
	PID    uint64
	Image  string
	Count  int
}

// DNSActivity is a sample-attributed, deduplicated view of DNS
// queries, with resolved addresses merged in from dns_query_result
// events for the same domain/process.
type DNSActivity struct {
	QueryName string
	PID       uint64
	Image     string
	Results   []string
	Count     int
}

// ImageActivity is a sample-attributed, deduplicated view of
// executable/DLL loads (excludes the trace-start image_dc_start
// rundown, which reflects modules already loaded before the trace
// began rather than activity performed by the sample).
type ImageActivity struct {
	Path          string
	PID           uint64
	Image         string
	ImageChecksum uint64
	Count         int
}