//go:build linux

// This program demonstrates attaching an eBPF program to a network interface
// with Linux TCX (Traffic Control with eBPF). The program counts ingress and egress
// packets using two variables. The userspace program (Go code in this file)
// prints the contents of the two variables to stdout every second.
// This example depends on tcx bpf_link, available in Linux kernel version 6.6 or newer.

package ebpf

import (
	"log"
	"net"
	"os"

	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	pathLatency = "/sys/fs/bpf/latency"
	pathDomain  = "/sys/fs/bpf/queryrecords"
	pathServer  = "/sys/fs/bpf/server_ip"
)

type linkPair struct {
	egressLink  *link.Link
	ingressLink *link.Link
}

type EbpfDaemon struct {
	objects           *bpfObjects
	interfaceLink     map[string]*linkPair
	pinnedLatency     *ebpf.Map
	pinnedQueryRecord *ebpf.Map
	pinnedServerIp    *ebpf.Map
}

func CreateDaemon() *EbpfDaemon {
	objects := &bpfObjects{}
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}
	if err := loadBpfObjects(objects, &opts); err != nil {
		log.Println("%v", err)
	}

	ebpfDaemon := &EbpfDaemon{
		objects:       objects,
		interfaceLink: make(map[string]*linkPair),
	}
	return ebpfDaemon
}

func (edaemon *EbpfDaemon) Attach(ifaceName string) error {

	iface, err := net.InterfaceByName(ifaceName)
	link1, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   edaemon.objects.IngressProgFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Printf("%v", err)
		return err
	}
	defer link1.Close()

	link2, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   edaemon.objects.EgressProgFunc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Printf("%v", err)
		return err
	}
	defer link2.Close()

	for true {

	}

	//edaemon.interfaceLink[ifaceName] = linkPair{egressLink: &link1, ingressLink: &link2}
	return nil

}

func (edaemon *EbpfDaemon) PinLatency() error {
	if err := edaemon.objects.Latency.Pin(pathLatency); err != nil && !os.IsExist(err) {
		log.Fatalf("failed to pin map: %v", err)
		return err
	}

	// Load the pinned map (safe if already pinned)
	pinnedLatency, err := ebpf.LoadPinnedMap(pathLatency, nil)
	if err != nil {
		log.Fatalf("failed to load pinned map: %v", err)
		return err
	}
	edaemon.pinnedLatency = pinnedLatency
	return nil

}

func (edaemon *EbpfDaemon) SetLatency(latency uint64) error {
	key := uint32(0) // Single entry key

	err := edaemon.objects.bpfMaps.Latency.Put(unsafe.Pointer(&key), unsafe.Pointer(&latency))
	if err != nil {
		return err
	}
	return nil

}
func (edaemon *EbpfDaemon) SetDynamicLatency(latency uint64) error {
	key := uint32(0)
	value := uint64(latency)
	if err := edaemon.pinnedLatency.Put(&key, &value); err != nil {
		log.Fatalf("failed to update map: %v", err)
		return err
	}
	return nil

}
func (edaemon *EbpfDaemon) EnableDomain() error {
	if err := edaemon.objects.Enabledomain.Pin("/sys/fs/bpf/enabledomain"); err != nil && !os.IsExist(err) {
		log.Fatalf("failed to pin map: %v", err)
		return err
	}

	// Load the pinned map (safe if already pinned)
	pinnedEnabledomain, err := ebpf.LoadPinnedMap("/sys/fs/bpf/enabledomain", nil)
	if err != nil {
		log.Fatalf("failed to load pinned map: %v", err)
		return err
	}
	key := uint32(0) // Single entry key
	value := uint32(1)

	err = pinnedEnabledomain.Put(&key, &value)
	if err != nil {
		return err
	}
	return nil
}

func (edaemon *EbpfDaemon) PinDomain() error {
	if err := edaemon.objects.Queryrecords.Pin(pathDomain); err != nil && !os.IsExist(err) {
		log.Fatalf("failed to pin map: %v", err)
		return err
	}

	// Load the pinned map (safe if already pinned)
	pinnedQueryRecord, err := ebpf.LoadPinnedMap(pathDomain, nil)
	if err != nil {
		log.Fatalf("failed to load pinned map: %v", err)
		return err
	}
	edaemon.pinnedQueryRecord = pinnedQueryRecord
	return nil
}

func (edaemon *EbpfDaemon) SetDomainDynamic(url string) error {

	query, err := createDnsQuery(url)
	if err != nil {
		return err
	}
	log.Printf("Domain added is : %s ", query.Name)
	value := uint32(1)

	err = edaemon.pinnedQueryRecord.Put(unsafe.Pointer(&(query.Name)), unsafe.Pointer(&value))
	if err != nil {
		return err
	}
	return nil
}
func (edaemon *EbpfDaemon) RemoveDomainDynamic(url string) error {

	query, err := createDnsQuery(url)
	if err != nil {
		return err
	}
	log.Printf("Domain removed is : %s ", query.Name)

	err = edaemon.pinnedQueryRecord.Delete(unsafe.Pointer(&(query.Name)))
	if err != nil {
		return err
	}
	return nil
}

func (edaemon *EbpfDaemon) EnableServer() error {
	if err := edaemon.objects.Enableserver.Pin("/sys/fs/bpf/enableserver"); err != nil && !os.IsExist(err) {
		log.Fatalf("failed to pin map: %v", err)
		return err
	}

	// Load the pinned map (safe if already pinned)
	pinnedEnableserver, err := ebpf.LoadPinnedMap("/sys/fs/bpf/enableserver", nil)
	if err != nil {
		log.Fatalf("failed to load pinned map: %v", err)
		return err
	}
	key := uint32(0) // Single entry key
	value := uint32(1)

	err = pinnedEnableserver.Put(&key, &value)
	if err != nil {
		return err
	}
	return nil

}
func (edaemon *EbpfDaemon) PinServer() error {
	if err := edaemon.objects.ServerIp.Pin(pathServer); err != nil && !os.IsExist(err) {
		log.Fatalf("failed to pin map: %v", err)
		return err
	}

	// Load the pinned map (safe if already pinned)
	pinnedServerIp, err := ebpf.LoadPinnedMap(pathDomain, nil)
	if err != nil {
		log.Fatalf("failed to load pinned map: %v", err)
		return err
	}
	edaemon.pinnedServerIp = pinnedServerIp
	return nil
}
func (edaemon *EbpfDaemon) SetServerDynamic(ip string) error {
	ip32, err := convertToUint32(ip)
	if err != nil {
		return err
	}
	value := uint32(1)
	err = edaemon.pinnedServerIp.Put(unsafe.Pointer(&(ip32)), unsafe.Pointer(&value))
	if err != nil {
		return err
	}
	return nil
}
func (edaemon *EbpfDaemon) RemoveServerDynamic(ip string) error {
	ip32, err := convertToUint32(ip)
	if err != nil {
		return err
	}
	err = edaemon.pinnedServerIp.Delete(unsafe.Pointer(&(ip32)))
	if err != nil {
		return err
	}
	return nil
}

/*func (edaemon *ebpfDaemon) Detach(ifaceName string) {
		link1 := edaemon.interfaceLink[ifaceName].ingressLink
		link2 := edaemon.interfaceLink[ifaceName].egressLink
		link1.Close()
		link2.Close()
		delete(ebpfDaemon.interfaceLink,ifaceName)
}*/
