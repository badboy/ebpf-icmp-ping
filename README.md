# Send ICMP Echo Replies using eBPF

The code parses the passed network packet into its Ethernet, IP and ICMP header,
swaps addresses (MAC and IP addresses), changes the ICMP type to `ICMP Echo Reply`,
re-calculates the ICMP checksum and sends the modified packet back out over the same interface.

## Run

First create a qdisc, then attach the classification and action, and at last show logging information:

```
make bpf.o
make qdisc
make run
make show exec
```

Delete filters and qdiscs afterwards:

```
make delete
make qdisc-delete
```
