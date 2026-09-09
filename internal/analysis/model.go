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