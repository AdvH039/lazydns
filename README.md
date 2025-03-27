# lazydns

## Description
configure and manage latency of dns packets dynamically.

## Dependencies
List the required dependencies to run the project.

-  Linux kernel version 6.6 or newer
-  Interface with configurable qdisc
-  go 1.23.4 or higher
-  amd64 processor (will make it processor agnostic in Makefile..(WIP))
  

## Setup and Installation
Step-by-step instructions to install and set up the project.

```sh
# Clone the repository
git clone https://github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039.git

# Navigate to the project directory
cd dns-query-delay-injector-ebpf-AdvH039

# For normal use build using :
make lazydns

# For contributors who want to make changes to ebpf source code use the build command :
go install github.com/cilium/ebpf/cmd/bpf2go@latest #Added dependency
make lazydns-dev

#Environment setup before execution

#1. Pick a routing interface and replace a qdisc with a fq disc else it will not work
sudo tc qdisc replace dev <interface_name> root fq

#2. Pinned Maps are used for real-time communication with user space, use the below command to ensure 
    /sys/fs/bpf is mounted
sudo mount -t bpf bpf /sys/fs/bpf




```


## Usage

```sh
#1. Use the below command to attach the tcx program to the interface and to obtain real-time logs. Must be used with
#admin access.
sudo ./lazydns add <interface_name>

#2 To configure latency run the below command in a new terminal while keeping the previous command running. Must also
#be used with admin access
sudo ./lazydns latency <latency_value>
```

## Testing
Currently I am using ping and noting the changes in rtt while modifying the latency. Demo and test suite with dns packets to be done.

## TODOS:
-  Filter dns packets only.
-  Calculate response time by using dns id as a unique identifier and log it using tcx.
-  Add hash maps that contain all the filter specific data(url,server ip) and cross check packets in tcx.
-  For process filtering an ebpf program and a tcx program must communicate through a hash map using dns id as a unique identifier (this will take time
-  :(  )


