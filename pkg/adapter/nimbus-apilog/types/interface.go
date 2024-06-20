package types

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/cilium/ebpf"
)

// NetInterface structure
type NetInterface struct {
	Name         string `json:"name" bson:"name"`
	Index        int    `json:"index" bson:"index"`
	Container    string `json:"container" bson:"container"`
	RingBufID    int
	EventMap     *ebpf.Map
	IsConnected  bool
	TotalPackets map[int]uint64
}

// NewNetInterface Function
func NewNetInterface(name string) (*NetInterface, error) {
	idx, err := interfaceNameToIndex(name)
	if err != nil {
		return nil, err
	}

	ret := &NetInterface{
		Name:         name,
		Index:        idx,
		Container:    "unknown",
		IsConnected:  false,
		TotalPackets: make(map[int]uint64),
	}

	// retrieve last ringbuffer map
	rbID, err := retrieveBpfMapID()
	if err != nil {
		return nil, err
	}

	ret.RingBufID = rbID
	return ret, nil
}

// ToString Function
func (ni *NetInterface) ToString() string {
	return fmt.Sprintf("name=%s, index=%d, container=%s, ringbuf_id=%d, is_connected=%v",
		ni.Name, ni.Index, ni.Container, ni.IsConnected)
}

// interfaceNameToIndex Function
func interfaceNameToIndex(name string) (int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return -1, err
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			return iface.Index, nil
		}
	}

	return -1, errors.New("interface not found")
}

// retrieveBpfMapID Function
// @todo: this currently utilizes bpftool map function,
// unfortunately cilium/ebpf shows pinned maps which are NOT
// perf ring buffers, so we need to use bpftool to get maps in the
// dirty way
func retrieveBpfMapID() (int, error) {
	// Execute the command
	output, err := exec.Command("bpftool", "map").CombinedOutput()
	if err != nil {
		fmt.Println("Error executing command:", err)
		return -1, err
	}

	// Define the regular expression pattern
	pattern := regexp.MustCompile(`(\d+): ringbuf\s+name events\s+flags 0x0\s+key 0B\s+value 0B\s+max_entries 16777216\s+memlock 0B`)

	// Find all matches in the output
	matches := pattern.FindAllStringSubmatch(string(output), -1)

	// If matches are found, print the last match
	if len(matches) > 0 {
		lastMatch := matches[len(matches)-1]
		if len(lastMatch) > 1 {
			val, err := strconv.Atoi(lastMatch[1])
			if err != nil {
				return -1, errors.New("last match not parsable")
			}

			return val, nil
		} else {
			return -1, errors.New("last match found, but can't extract")
		}
	} else {
		return -1, errors.New("no entry found")
	}
}
