package cmd

import (
	//"os"
	"log"
	//"bufio"
	//"time"

	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/daemon"
	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/daemon/debug"
	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/utils"
	"github.com/spf13/cobra"
)

func NewAdditionCmd(backend *daemon.AppBackend) *cobra.Command {
	var addCmd = &cobra.Command{
		Use:   "add [interface]",
		Short: "Attach an eBPF program to a network interface",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {

			ifaceName := args[0]

			dbgDaemon, err := debug.CreateDaemon()
			if err != nil {
				log.Println("Error creating debug daemon : %v", err)
			}
			backend.DbgDaemon = dbgDaemon

			err = backend.BpfDaemon.SetLatency(utils.DnsLatency)
			if err != nil {
				log.Println("Could not set latency")
				return
			}

			/*err=backend.ebpfDaemon.SetLatency(utils.DnsLatency)
			if err != nil {
				log.Println("Could not set latency")
			}*/
			backend.StartDaemon(ifaceName)

		},
	}
	return addCmd

}
