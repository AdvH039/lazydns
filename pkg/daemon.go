package pkg

import (
	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/pkg/debug"
	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/pkg/ebpf"
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
