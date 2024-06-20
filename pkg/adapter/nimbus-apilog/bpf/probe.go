package bpf

import (
	"BeeCol/exporter"
	"BeeCol/parser"
	"BeeCol/types"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/cilium/ebpf/rlimit"
)

var BpfObjects bpfObjects
var Bh *BpfHandler

// BpfHandler Structure
type BpfHandler struct {
	ifaceChan chan *types.NetInterface
	isStopped bool
}

func init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	if err := loadBpfObjects(&BpfObjects, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
}

// NewBpfHandler Function
func NewBpfHandler() *BpfHandler {
	return &BpfHandler{
		ifaceChan: make(chan *types.NetInterface),
		isStopped: true,
	}
}

// ifaceInsertRoutine Function
func (Bh *BpfHandler) ifaceInsertRoutine() error {
	for {
		select {
		case c := <-Bh.ifaceChan:
			eventMap, err := ebpf.NewMapFromID(ebpf.MapID(c.RingBufID))
			if err != nil {
				log.Printf("Unable to load perf map %d for interface %s(%d): %v",
					c.RingBufID, c.Name, c.Index, err)
				continue
			}

			go func() {
				err = Bh.ifaceReadRoutine(eventMap)
				if err != nil {
					log.Printf("Unable to perform perf map read routine for interface %s(%d): %v",
						c.Name, c.Index, err)
				}
			}()
		}
	}
}

// ifaceReadRoutine Function
func (Bh *BpfHandler) ifaceReadRoutine(eventMap *ebpf.Map) error {
	rd, err := ringbuf.NewReader(eventMap)
	if err != nil {
		return err
	}

	var event bpfEvent
	for {
		if Bh.isStopped {
			break
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				break
			}
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		go func() {
			// Process, show the results
			packet := processEvent(event)
			strProto := "Unknown"
			strDirection := "Unknown"

			switch packet.ProtoType {
			case 1:
				strProto = "TCP"
			case 2:
				strProto = "UDP"
			case 3:
				strProto = "SCTP"
			default:
				strProto = "Unknown"
			}

			switch packet.Direction {
			case 1:
				strDirection = "Ingress"
			case 2:
				strDirection = "Egress"
			}

			if packet.ProtoType == 2 {
				fmt.Println("-------------------------")
				fmt.Printf("[%s] %s:%d -> %s:%d (%s)\n", strProto, packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort, strDirection)
				parser.ParseRLSProtocol31(packet.Payload)
				parser.ParseRLSProtocol32(packet.Payload)
			} else if packet.ProtoType == 3 {
				fmt.Println("-------------------------")
				fmt.Printf("[%s] %s:%d -> %s:%d (%s)\n", strProto, packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort, strDirection)
				fmt.Printf("%s", packet.Payload)
			} else if packet.ProtoType == 1 {
				// parse HTTP request Header
				httpRequest, err := parser.ParseHTTPRequest(packet)
				if err == nil {
					_ = exporter.HTTPEx.InsertHTTPLog(httpRequest)
				}

				// parse HTTP response Header
				httpResponse, err := parser.ParseHTTPResponse(packet)
				if err == nil {
					_ = exporter.HTTPEx.InsertHTTPLog(httpResponse)
				}
			}
		}()
	}

	return nil
}

// Run Function
func (Bh *BpfHandler) Run() {
	Bh.isStopped = false
	err := Bh.ifaceInsertRoutine()
	if err != nil {
		log.Fatal(err)
	}
}

// Stop Function
func (Bh *BpfHandler) Stop() {
	Bh.isStopped = true
}
