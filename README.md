# Send ICMP Echo Replies using eBPF

The code parses the passed network packet into its Ethernet, IP and ICMP header,
swaps addresses (MAC and IP addresses), changes the ICMP type to `ICMP Echo Reply`,
re-calculates the ICMP checksum and sends the modified packet back out over the same interface.

## Requirements

* A recent kernel. Tested with 4.8 and 4.9
* `iproute2 v4.9`. v4.10 has a bug making it unusable.
  If your system does not provide it,
  compile it from [git](https://wiki.linuxfoundation.org/networking/iproute2).
  Installation is not needed, the `tc` binary is enough.
* Clang `>= 3.8`. eBPF backend required.

Code was tested on Ubuntu 16.10 with self-compiled iproute2 v4.9 and clang 4.0.


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

## The code

The code in [`bpf.c`](bpf.c) is commented to explain each step.

## Resources

* [ebpf-trekking](https://github.com/muhammadzaheer/ebpf-trekking/blob/master/treks/ping_reply/ping_reply.py), an implementation using [bcc](https://github.com/iovisor/bcc)
