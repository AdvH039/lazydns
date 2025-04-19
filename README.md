# Lazydns

## Description
Lazydns allows you to dynamically configure latency and filter DNS packets in real time.

## Dependencies
List the required dependencies to run the project.

-  Linux kernel version `6.6` or newer
-  Interface with configurable qdisc
-  `go 1.23.4` or higher
-  amd64 processor (will make it processor agnostic in Makefile..(WIP))
  

## Setup and Installation
Step-by-step instructions to install and set up the project.


Clone the repository
```bash
git clone https://github.com/NetworkInCode/dns-query-delay-injector-ebpf-AdvH039.git
```

Navigate to the project directory
```bash
cd dns-query-delay-injector-ebpf-AdvH039
```

For standard usage, build using:
```bash
make lazydns
```

For contributors modifying the eBPF source code, use:
```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest #Added dependency
make lazydns-dev
```
To format the codebase, run:
```bash
make format
```

## Step 1 :Environment setup before usage

1.Choose a network interface and replace its qdisc with an `fq` (fair queuing) disc to ensure proper operation:
```bash
sudo tc qdisc replace dev <interface_name> root fq
```

2. Lazydns uses pinned maps for real-time communication between kernel and user space. Ensure `/sys/fs/bpf/` is mounted:
```bash
sudo mount -t bpf bpf /sys/fs/bpf/
```

## Step 2 :Enabling filters (Optional) 
Before attaching the `tcx` programs responsible for packet delay, enable the necessary filters. DNS packets matching these filters will be delayed.

### 1. Filtering by Server IP (Destination IP of DNS packets)

Currently, only IPv4 is supported.

```bash
sudo ./lazydns server on
```
### 2. Filtering by URL (Domain Name)

DNS packets querying a specified domain name will be filtered.
```bash
sudo ./lazydns server on
```

## Step 3 :Attaching the `tcx` program
Attach an ingress and egress `tcx` program to a chosen interface. The egress program applies latency to filtered packets and records their outgoing time, while the ingress program records the incoming time and calculates the overall response time when receiving a corresponding response.
```bash
sudo ./lazydns add <interface_name>
```
## Step 4 : Dynamic Configuration of Latency

You can set the latency before or during the attachment of the ``tcx`` program. The value is specified in nanoseconds:
```bash
sudo ./lazydns latency <latency_value>
```

## Step 5 :Dynamic Addition of filters  (Requires Step 2) 

### Filtering by Server IP
If the server filter is enabled, you can add or remove IPs dynamically.

Add a server IP to filter:
```bash
sudo ./lazydns server add <server_ip>
```


Remove a server IP from the filter:
```bash
sudo ./lazydns server delete <server_ip>
```
If a packet's destination matches one of the filtered server IPs, it will be delayed. You can add or remove IPs before or during `tcx` program attachment, but ensure the server filter is enabled first.

### Filtering by Target Url

If the URL filter is enabled, you can add or remove target URLs dynamically.

Add a target URL to filter:
```bash
sudo ./lazydns server add <target_url> 
```


Remove a target URL from the filter:
```bash
sudo ./lazydns server delete <target_url>
```

If a packet queries any of the added domains, it will be delayed. URLs can be added or removed before or during the attachment of the `tcx` program, but ensure the URL filter is enabled first.

## Testing
Users can maunually test by executing the commands and noting the latency and other dns related information described in the logs.

## TODOS
- Testing - I have to come up with a setting that does not decrease the response time of the packet with every iteration. I tried a simple local server and client but the packet doesn't seem to pass through the routing interface. Right now the ebpf program only responds to dns packets but I found the best way to test the logic of the qdisc was through ping and allow the ebpf program to accept all packets.

-  For process-based filtering a cgroup-egress program and a `tcx` program must communicate through a hash map using dns id as a unique identifier. (this will take time.) Containers would be uniquely identified by their cgroup id and every container will have a cgroup-egress program hooked to its cgroup path that lists all the dns ids of all dns packets that pass through it in a map which is shared with the tcx program that adds latency to only those listed ids. ~~~I was able to hook the program to a specific cgroup successfully but was not able to parse the ethernet hdr. It was not a normal ip packet.    :(  )~~~ I have to parse the packet starting from ip header in the cgroup as it does not have ethernet header.

- ~~Automate qdisc replacement~~

- Support lower kernel versions( Use tc library itself for attaching programs?)

- Use interfaces to make filter development clean and uniform (What is the best design implementation ?)

- Use a yaml format to employ better schema for filters? How translate the filter schema within the ebpf program?(Advanced)


![Screenshot from 2025-03-26 19-33-19](https://github.com/user-attachments/assets/1618eab8-ac79-4936-8380-f7243c713096)



