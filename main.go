package main

import (
	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/cmd"
	"github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039/pkg"
	"github.com/spf13/cobra"
	"os"
)

func main() {
	backend := pkg.NewAppBackend()
	rootCmd := &cobra.Command{
		Use:   "lazydns",
		Short: "lazydns - An eBPF-based DNS manipulation tool",
		Long:  `lazydns allows users to dynamically configure the latency of dns packets moving through a network interface.`,
	}

	rootCmd.AddCommand(cmd.NewAdditionCmd(backend))
	rootCmd.AddCommand(cmd.NewLatencySubCmd(backend))
	rootCmd.AddCommand(cmd.NewUrlCmd(backend))
	rootCmd.AddCommand(cmd.NewServerCmd(backend))

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}

}
