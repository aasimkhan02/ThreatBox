package analysis

import (
	"bufio"
	"errors"
	"strings"
)

func Collect(rawStrace string) ([]Event, error) {
	
	var events []Event

	scanner := bufio.NewScanner(strings.NewReader(rawStrace))

	for scanner.Scan() {
		line := scanner.Text()

		event, err := Parse(line)
		if err != nil {
			// A syscall we haven't implemented a handler for yet (brk, mmap,
			// execve, ...) is expected and shouldn't kill the whole
			// collection - just skip that line.
			if errors.Is(err, ErrUnsupportedSyscall) {
				continue
			}
			// Anything else (empty line, line that doesn't match the
			// expected shape at all) is a real problem worth surfacing.
			return nil, err
		}

		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
        return nil, err
    }
	
	return events, nil
}