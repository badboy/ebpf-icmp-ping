#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <stddef.h>

#include "bpf_helpers.h"

#define trace_printk(fmt, ...) do { \
	char _fmt[] = fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
	} while (0)

/* compiler workaround */
#define bpf_htonl __builtin_bswap32
#define bpf_memcpy __builtin_memcpy

#define ICMP_PING 8

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

SEC("classifier")
int cls_main(struct __sk_buff *skb)
{
	return -1;
}

SEC("action")
int pingpong(struct __sk_buff *skb)
{
	/* We will access all data through pointers to structs */
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	/* first we check that the packet has enough data,
	 * so we can access the three different headers of ethernet, ip and icmp
	 */
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
		return TC_ACT_UNSPEC;

	/* for easy access we re-use the Kernel's struct definitions */
	struct ethhdr  *eth  = data;
	struct iphdr   *ip   = (data + sizeof(struct ethhdr));
	struct icmphdr *icmp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

	/* Only actual IP packets are allowed */
	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	/* We handle only ICMP traffic */
	if (ip->protocol != IPPROTO_ICMP)
		return TC_ACT_UNSPEC;

	/* ...and only if it is an actual incoming ping */
	if (icmp->type != ICMP_PING)
		return TC_ACT_UNSPEC;

	/* Let's grab the MAC address.
	 * We need to copy them out, as they are 48 bits long */
	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
	bpf_memcpy(src_mac, eth->h_source, ETH_ALEN);
	bpf_memcpy(dst_mac, eth->h_dest, ETH_ALEN);

	/* Let's grab the IP addresses.
	 * They are 32-bit, so it is easy to access */
	__u32 src_ip = ip->saddr;
	__u32 dst_ip = ip->daddr;

#ifdef DEBUG
	trace_printk("[action] IP Packet, proto= %d, src= %lu, dst= %lu\n", ip->protocol, src_ip, dst_ip);
#endif

	/* Swap the MAC addresses */
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);

	/* Swap the IP addresses.
	 * IP contains a checksum, but just swapping bytes does not change it.
	 * so no need to recalculate */
	bpf_skb_store_bytes(skb, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
	bpf_skb_store_bytes(skb, IP_DST_OFF, &src_ip, sizeof(src_ip), 0);

	/* Change the type of the ICMP packet to 0 (ICMP Echo Reply).
	 * This changes the data, so we need to re-calculate the checksum
	 */
	__u8 new_type = 0;
	/* We need to pass the full size of the checksum here (2 bytes) */
	bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, ICMP_PING, new_type, ICMP_CSUM_SIZE);
	bpf_skb_store_bytes(skb, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);

	/* Now redirecting the modified skb on the same interface to be transmitted again */
	bpf_clone_redirect(skb, skb->ifindex, 0);

	/* We modified the packet and redirected it, it can be dropped here */
	return TC_ACT_SHOT;
}

char __license[] SEC("license") = "GPL";
