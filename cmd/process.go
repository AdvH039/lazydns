package cmd

import (
	//"os"
	"log"

	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/daemon"
	"github.com/spf13/cobra"
	//"bufio"
	//"time"
)

func NewProcessCmd(backend *daemon.AppBackend) *cobra.Command {

	processCmd := &cobra.Command{
		Use:   "process",
		Short: "Filter target processs dynamically",

		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	onProcessCmd := &cobra.Command{
		Use:   "on",
		Short: "Enable target process filtering",
		Run: func(cmd *cobra.Command, args []string) {
			err := backend.BpfDaemon.EnableProcess()
			if err != nil {
				log.Printf("Could not enable domain configuration %v", err)
			}

		},
	}
	addProcessCmd := &cobra.Command{
		Use:   "add [container id]",
		Short: "Adds process whose latency you would like to target",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			containerID := args[0]

			err := backend.BpfDaemon.PinProcess()
			if err != nil {
				log.Printf("Could not configure process : %v", err)
			}

			err = backend.BpfDaemon.SetProcessDynamic(containerID)
			if err != nil {
				log.Printf("Could not configure process : %v", err)
			}

		},
	}

	delProcessCmd := &cobra.Command{
		Use:   "del [target process']",
		Short: "Removes target process",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			containerID := args[0]

			err := backend.BpfDaemon.PinProcess()
			if err != nil {
				log.Printf("Could not configure process : %v", err)
			}

			err = backend.BpfDaemon.RemoveProcessDynamic(containerID)
			if err != nil {
				log.Printf("Could not configure process : %v", err)
			}

		},
	}

	processCmd.AddCommand(addProcessCmd)
	processCmd.AddCommand(delProcessCmd)
	processCmd.AddCommand(onProcessCmd)

	return processCmd

}
