package daemon

import (
	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/daemon/debug"
	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/daemon/ebpf"
)

type AppBackend struct {
	BpfDaemon *ebpf.EbpfDaemon
	DbgDaemon *debug.DebugDaemon
}

func NewAppBackend() *AppBackend {

	return &AppBackend{
		BpfDaemon: ebpf.CreateDaemon(),
	}
}

func (backend *AppBackend) StartDaemon(ifaceName string) {
	backend.DbgDaemon.Log()
	backend.BpfDaemon.Attach(ifaceName)

}
