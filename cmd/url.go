package cmd

import (
	//"os"
	"log"

	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/pkg"
	"github.com/spf13/cobra"
	//"bufio"
	//"time"
)

func NewUrlCmd(backend *pkg.AppBackend) *cobra.Command {

	urlCmd := &cobra.Command{
		Use:   "url",
		Short: "Filter target urls dynamically",

		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	onUrlCmd := &cobra.Command{
		Use:   "on",
		Short: "Enable target url filtering",
		Run: func(cmd *cobra.Command, args []string) {
			err := backend.BpfDaemon.EnableDomain()
			if err != nil {
				log.Printf("Could not enable domain configuration %v", err)
			}

		},
	}
	addUrlCmd := &cobra.Command{
		Use:   "add [target url]",
		Short: "Adds url whose latency you would like to target",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			url := args[0]

			err := backend.BpfDaemon.PinDomain()
			if err != nil {
				log.Printf("Could not configure url : %v", err)
			}

			err = backend.BpfDaemon.SetDomainDynamic(url)
			if err != nil {
				log.Printf("Could not configure url : %v", err)
			}

		},
	}

	delUrlCmd := &cobra.Command{
		Use:   "del [target url]",
		Short: "Removes target url",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			url := args[0]

			err := backend.BpfDaemon.PinDomain()
			if err != nil {
				log.Printf("Could not configure url : %v", err)
			}

			err = backend.BpfDaemon.RemoveDomainDynamic(url)
			if err != nil {
				log.Printf("Could not configure url : %v", err)
			}

		},
	}

	urlCmd.AddCommand(addUrlCmd)
	urlCmd.AddCommand(delUrlCmd)
	urlCmd.AddCommand(onUrlCmd)

	return urlCmd

}
