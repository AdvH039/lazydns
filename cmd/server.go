package cmd

import (
	//"os"
	"log"

	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/pkg"
	"github.com/spf13/cobra"
	//"bufio"
	//"time"
)

func NewServerCmd(backend *pkg.AppBackend) *cobra.Command {

	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Filter target servers dynamically",

		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	onServerCmd := &cobra.Command{
		Use:   "on",
		Short: "Enable target server filtering",
		Run: func(cmd *cobra.Command, args []string) {
			err := backend.BpfDaemon.EnableServer()
			if err != nil {
				log.Printf("Could not enable domain configuration %v", err)
			}

		},
	}
	addServerCmd := &cobra.Command{
		Use:   "add [target server]",
		Short: "Adds servers whose latency you would like to target",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			server := args[0]

			err := backend.BpfDaemon.PinServer()
			if err != nil {
				log.Printf("Could not configure server : %v", err)
			}

			err = backend.BpfDaemon.SetServerDynamic(server)
			if err != nil {
				log.Printf("Could not configure server : %v", err)
			}

		},
	}

	delServerCmd := &cobra.Command{
		Use:   "del [target server']",
		Short: "Removes target server",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			server := args[0]

			err := backend.BpfDaemon.PinServer()
			if err != nil {
				log.Printf("Could not configure server : %v", err)
			}

			err = backend.BpfDaemon.RemoveServerDynamic(server)
			if err != nil {
				log.Printf("Could not configure server : %v", err)
			}

		},
	}

	serverCmd.AddCommand(addServerCmd)
	serverCmd.AddCommand(delServerCmd)
	serverCmd.AddCommand(onServerCmd)

	return serverCmd

}
