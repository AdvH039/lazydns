package cmd

import (
	"fmt"
	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/pkg"
	"github.com/spf13/cobra"
	"strconv"
)

func NewLatencySubCmd(backend *pkg.AppBackend) *cobra.Command {

	var latencyCmd = &cobra.Command{
		Use:   "latency [value]",
		Short: "Set DNS query latency delay (in nanoseconds)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {

			latency, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				fmt.Println("Invalid latency value. Please provide a number.")
				return
			}
			err = backend.BpfDaemon.PinLatency()
			if err != nil {
				fmt.Println("Could not Pin map")
				return
			}

			err = backend.BpfDaemon.SetDynamicLatency(latency)
			if err != nil {
				fmt.Println("Could not set latency")
				return
			}

		},
	}
	return latencyCmd
}
