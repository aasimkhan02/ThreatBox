package analysis

import (
    "errors"
    "fmt"
    "regexp"
    "strconv"
    "strings"
)

// ErrUnsupportedSyscall means the line parsed fine (pid, syscall name, args,
// return value all extracted) but we don't have a handler for this syscall
// yet. This is expected and common (brk, mmap, execve, ...) and callers
// should skip these lines rather than treat them as failures.
var ErrUnsupportedSyscall = errors.New("unsupported syscall")

// Matches the general shape of a strace line, e.g.:
//   1234  openat(AT_FDCWD, "/tmp/test.txt", O_WRONLY|O_CREAT, 0644) = 3
// Captures: pid, syscall name, raw args, return value.
var lineRegex = regexp.MustCompile(`^(\d+)\s+(\w+)\((.*)\)\s*=\s*(.+)$`)

// Matches the first quoted string in an argument list, e.g. the path in
// openat's args or the buffer in write's args.
var quotedRegex = regexp.MustCompile(`"([^"]*)"`)

// Parse turns a single line of strace output into an Event.
//
// Fields strace's default output can't give us (Process name, Timestamp)
// are intentionally left zero-valued here rather than guessed at. Process
// could later be filled in by the collector, since it knows which binary
// it launched. Timestamp would require re-running strace with -tt and
// parsing that prefix - not done yet.
func Parse(line string) (Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Event{}, fmt.Errorf("empty strace line")
	}

	matches := lineRegex.FindStringSubmatch(line)
	if matches == nil {
		return Event{}, fmt.Errorf("malformed strace line: %q", line)
	}

	pidStr, syscall, args, ret := matches[1], matches[2], matches[3], strings.TrimSpace(matches[4])

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return Event{}, fmt.Errorf("invalid pid %q: %w", pidStr, err)
	}

	event := Event{
		PID:      pid,
		Source:   "strace",
		Metadata: make(map[string]string),
	}

	switch syscall {
	case "openat":
		return parseOpenat(event, args, ret)
	case "write":
		return parseWrite(event, args, ret)
	case "close":
		return parseClose(event, args, ret)
	default:
		return Event{}, fmt.Errorf("%w: %s", ErrUnsupportedSyscall, syscall)
	}
}

// openat(AT_FDCWD, "/tmp/test.txt", O_WRONLY|O_CREAT, 0644) = 3
func parseOpenat(event Event, args, ret string) (Event, error) {
	m := quotedRegex.FindStringSubmatch(args)
	if m == nil {
		return Event{}, fmt.Errorf("openat: could not find path in args %q", args)
	}

	event.Type = EventFileOpen
	event.Target = m[1]
	event.Metadata["return"] = ret // returned fd (or -1 on error)
	return event, nil
}

// write(3, "hello", 5) = 5
func parseWrite(event Event, args, ret string) (Event, error) {
	parts := strings.SplitN(args, ",", 2)
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return Event{}, fmt.Errorf("write: malformed args %q", args)
	}
	fd := strings.TrimSpace(parts[0])

	event.Type = EventFileWrite
	// We don't yet track which path an fd maps to, so the fd itself is the
	// best target we have at this stage.
	event.Target = fd
	if m := quotedRegex.FindStringSubmatch(args); m != nil {
		event.Metadata["data"] = m[1]
	}
	event.Metadata["return"] = ret // bytes actually written
	return event, nil
}

// close(3) = 0
func parseClose(event Event, args, ret string) (Event, error) {
	fd := strings.TrimSpace(args)
	if fd == "" {
		return Event{}, fmt.Errorf("close: malformed args %q", args)
	}

	event.Type = EventFileClose
	event.Target = fd
	event.Metadata["return"] = ret
	return event, nil
}