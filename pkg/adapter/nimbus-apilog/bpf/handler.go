package bpf

import (
	"BeeCol/types"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
)

var TCH *TCHandler

// TCHandler Structure
type TCHandler struct {
	interfaces map[int][]*types.NetInterface
	lock       sync.Mutex
	isRunning  bool
}

// NewTCHandler Function
func NewTCHandler() *TCHandler {
	TCH = &TCHandler{
		interfaces: make(map[int][]*types.NetInterface),
		lock:       sync.Mutex{},
		isRunning:  false,
	}

	return TCH
}

// RunWatchRoutine Function
func (tch *TCHandler) RunWatchRoutine() {
	tch.isRunning = true

	go func() {
		for {
			newIfaces, err := tch.scanInterfaces()
			if err != nil {
				continue
			}

			if len(newIfaces) != 0 {
				log.Printf("%d new interfaces found", len(newIfaces))
			}

			for _, iface := range newIfaces {
				log.Printf("Attaching TC to interface %s(%d)", iface.Name, iface.Index)
				// critical section for tch
				tch.lock.Lock()

				tcIngress, err := tch.AttachTCIngress(iface)
				if err != nil {
					log.Printf("Unable to attach TC ingress to interface %s(%d): %v", iface.Name, iface.Index, err)
				} else {
					log.Printf("Successfully attached TC ingress to interface %s(%d)", iface.Name, iface.Index)
				}

				tcEgress, err := tch.AttachTCEgress(iface)
				if err != nil {
					log.Printf("Unable to attach TC egresss to interface %s(%d): %v", iface.Name, iface.Index, err)
				} else {
					log.Printf("Successfully attached TC egress to interface %s(%d)", iface.Name, iface.Index)
				}

				res := []*types.NetInterface{
					tcIngress,
					tcEgress,
				}

				log.Printf("Successfully attached TC to interface %s(%d)", iface.Name, iface.Index)
				tch.interfaces[iface.Index] = res
				tch.lock.Unlock()
			}

			if !tch.isRunning {
				tch.unloadAllTC()
			}
		}
	}()
}

// scanInterfaces Function
func (tch *TCHandler) scanInterfaces() ([]net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error retrieving interfaces: %w", err)
	}

	// @todo: fix this actually detect veth. for now this will just identify those interfaces starting with
	// specific prefixes, so we need to fix this! (ip -details link show -> shows veth)
	allInterfaces := make([]net.Interface, 0)
	for _, iface := range interfaces {
		//if strings.Contains(iface.Name, "veth") || strings.Contains(iface.Name, "cali") || strings.Contains(iface.Name, "eth") {
		if true {
			allInterfaces = append(allInterfaces, iface)
		}
	}

	allInterfaces = append(allInterfaces, net.Interface{
		Name: "eth0", Index: 2,
	})

	// look for new interfaces
	ret := make([]net.Interface, 0)
	for _, iface := range allInterfaces {
		if _, ok := tch.interfaces[iface.Index]; !ok {
			ret = append(ret, iface)
		}
	}

	return ret, nil
}

// AttachTCIngress Function
func (tch *TCHandler) AttachTCIngress(iface net.Interface) (*types.NetInterface, error) {
	cmds := []string{
		fmt.Sprintf("tc qdisc add dev %s ingress", iface.Name),
		fmt.Sprintf("tc filter add dev %s ingress bpf da obj bpf/bpf_x86_bpfel_tc.o sec ingress", iface.Name),
		fmt.Sprintf("tc filter show dev %s ingress", iface.Name),
		//fmt.Sprintf("tc -n 1549332 qdisc add dev %s ingress", "eth0"),
		//	fmt.Sprintf("tc -n 1549332 filter add dev %s ingress bpf da obj bpf/bpf_x86_bpfel_tc.o sec ingress", "eth0"),
		//	fmt.Sprintf("tc -n 1549332 filter show dev %s ingress", "eth0"),
	}

	// execute each command
	for idx, cmd := range cmds {
		command := exec.Command("bash", "-c", cmd)
		output, err := command.CombinedOutput()
		if err != nil && idx != 0 {
			msg := fmt.Sprintf("error executing command '%s': %v, output: %s", cmd, err, string(output))
			return nil, errors.New(msg)
		}

		if idx == 2 {
			outputStr := fmt.Sprintf("%s", output)
			if !strings.ContainsAny(outputStr, iface.Name) && !strings.ContainsAny(outputStr, "ingress") {
				return nil, errors.New("unable to verify using tc filter show")
			}
		}
	}

	tcIface, err := types.NewNetInterface(iface.Name)
	if err != nil {
		return nil, err
	}

	go func() {
		Bh.ifaceChan <- tcIface
	}()

	return tcIface, nil
}

// AttachTCEgress Function
func (tch *TCHandler) AttachTCEgress(iface net.Interface) (*types.NetInterface, error) {
	cmds := []string{
		fmt.Sprintf("tc qdisc add dev %s clsact", iface.Name),
		fmt.Sprintf("tc filter add dev %s egress bpf da obj bpf/bpf_x86_bpfel_tc.o sec egress", iface.Name),
		fmt.Sprintf("tc filter show dev %s egress", iface.Name),
		//fmt.Sprintf("tc -n 1549332 qdisc add dev %s clsact", "eth0"),
		//fmt.Sprintf("tc -n 1549332 filter add dev %s egress bpf da obj bpf/bpf_x86_bpfel_tc.o sec egress", "eth0"),
		//fmt.Sprintf("tc -n 1549332 filter show dev %s egress", "eth0"),
	}

	// execute each command
	for idx, cmd := range cmds {
		command := exec.Command("bash", "-c", cmd)
		output, err := command.CombinedOutput()
		if err != nil && idx != 0 {
			msg := fmt.Sprintf("error executing command '%s': %v, output: %s", cmd, err, string(output))
			return nil, errors.New(msg)
		}

		if idx == 2 {
			outputStr := fmt.Sprintf("%s", output)
			if !strings.ContainsAny(outputStr, iface.Name) && !strings.ContainsAny(outputStr, "ingress") {
				return nil, errors.New("unable to verify using tc filter show")
			}
		}
	}

	tcIface, err := types.NewNetInterface(iface.Name)
	if err != nil {
		return nil, err
	}

	go func() {
		Bh.ifaceChan <- tcIface
	}()

	return tcIface, nil
}

// UnloadTC Function
func (tch *TCHandler) UnloadTC(iface types.NetInterface) error {
	cmds := []string{
		fmt.Sprintf("sudo tc filter del dev %s ingress", iface.Name),
		fmt.Sprintf("sudo tc filter del dev %s egress", iface.Name),
		fmt.Sprintf("tc qdisc del dev %s clsact", iface.Name),
	}

	for _, cmd := range cmds {
		command := exec.Command("bash", "-c", cmd)
		_, err := command.CombinedOutput()
		if err != nil {
			msg := fmt.Sprintf("unable to unload TC using %s: %v", cmd, err)
			return errors.New(msg)
		}
	}

	return nil
}

// unloadAllTC Function
func (tch *TCHandler) unloadAllTC() {
	errCount := 0
	failedInterfaces := make([]string, 0)
	for _, tcIfaces := range tch.interfaces {
		for _, tcIface := range tcIfaces {
			err := tch.UnloadTC(*tcIface)
			if err != nil {
				errCount++
				log.Printf("Failed to unload TC from interface %s(%d), errCount=%d : %v",
					tcIface.Name, tcIface.Index, errCount, err)
			} else {
				log.Printf("Successfully unloaded TC egress/ingress from %s(%d)", tcIface.Name, tcIface.Index)
			}

			failedInterfaces = append(failedInterfaces, tcIface.Name)
		}
	}

	if errCount != 0 {
		log.Printf("Unable to load some of the interfaces: %v", failedInterfaces)
	}
}
