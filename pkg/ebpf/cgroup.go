package ebpf

import (
	"context"
	"fmt"
	"github.com/docker/docker/client"
	"golang.org/x/sys/unix"
	"os"
	"regexp"
)

const (
	pathProcMounts = "/proc/mounts"
)

var reCgroup2Mount = regexp.MustCompile(`(?m)^cgroup2\s(/\S+)\scgroup2\s`)

func GetCgroupV2RootDir() (string, error) {
	p, err := getCgroupV2RootDir(pathProcMounts)
	return p, err
}

func getCgroupV2RootDir(pathProcMounts string) (string, error) {
	data, err := os.ReadFile(pathProcMounts)
	if err != nil {
		return "", err
	}
	items := reCgroup2Mount.FindStringSubmatch(string(data))
	if len(items) < 2 {
		return "", err
	}
	return items[1], nil
}

func getCgroupID(containerID string) (uint64, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return 0, err
	}
	defer cli.Close()

	// Inspect the container to get process details
	container, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return 0, err
	}

	// Get the PID of the container's main process
	pid := container.State.Pid

	// Construct the cgroup path from /proc
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	file, err := os.Open(cgroupPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	// Use inode number to get the cgroup ID
	var stat unix.Stat_t
	if err := unix.Stat(cgroupPath, &stat); err != nil {
		return 0, err
	}

	return stat.Ino, nil
}
