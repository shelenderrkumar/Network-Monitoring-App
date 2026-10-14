// SPDX-License-Identifier: GPL-2.0
/*
 * XDP blocklist: drops packets whose source OR destination address is in a
 * blocklist map, before the kernel allocates an skb for them.
 *
 * - IPv4 and IPv6, with up to two VLAN tags (802.1Q / 802.1ad).
 * - Each blocklist entry counts the packets and bytes it dropped, so user
 *   space can show which blocked destinations are still being contacted.
 * - Global pass/drop counters live in a per-CPU array (no cross-CPU contention).
 *
 * Maps are pinned by name so the user-space controller can update them through
 * /sys/fs/bpf without recompiling or reloading the program.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_BLOCKED 65536

struct counters {
	__u64 packets;
	__u64 bytes;
};

struct vlan_hdr {
	__be16 tci;
	__be16 encapsulated_proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); /* IPv4 address, network byte order */
	__type(value, struct counters);
	__uint(max_entries, MAX_BLOCKED);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct in6_addr);
	__type(value, struct counters);
	__uint(max_entries, MAX_BLOCKED);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist_v6 SEC(".maps");

enum { STAT_PASS = 0, STAT_DROP = 1, STAT_MAX };

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct counters);
	__uint(max_entries, STAT_MAX);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats SEC(".maps");

static __always_inline int account(__u32 verdict, __u64 bytes)
{
	__u32 key = verdict == XDP_DROP ? STAT_DROP : STAT_PASS;
	struct counters *c = bpf_map_lookup_elem(&xdp_stats, &key);

	if (c) { /* per-CPU slot: no atomics needed */
		c->packets++;
		c->bytes += bytes;
	}
	return verdict;
}

static __always_inline int drop(struct counters *hit, __u64 bytes)
{
	__sync_fetch_and_add(&hit->packets, 1);
	__sync_fetch_and_add(&hit->bytes, bytes);
	return account(XDP_DROP, bytes);
}

SEC("xdp")
int xdp_blocklist(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 bytes = data_end - data;
	struct ethhdr *eth = data;
	struct counters *hit;
	void *cursor;
	__u16 proto;

	if ((void *)(eth + 1) > data_end)
		return account(XDP_PASS, bytes);
	proto = eth->h_proto;
	cursor = eth + 1;

#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
			break;
		struct vlan_hdr *vlan = cursor;
		if ((void *)(vlan + 1) > data_end)
			return account(XDP_PASS, bytes);
		proto = vlan->encapsulated_proto;
		cursor = vlan + 1;
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = cursor;
		if ((void *)(ip + 1) > data_end)
			return account(XDP_PASS, bytes);
		hit = bpf_map_lookup_elem(&blocklist_v4, &ip->saddr);
		if (!hit)
			hit = bpf_map_lookup_elem(&blocklist_v4, &ip->daddr);
		if (hit)
			return drop(hit, bytes);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = cursor;
		if ((void *)(ip6 + 1) > data_end)
			return account(XDP_PASS, bytes);
		hit = bpf_map_lookup_elem(&blocklist_v6, &ip6->saddr);
		if (!hit)
			hit = bpf_map_lookup_elem(&blocklist_v6, &ip6->daddr);
		if (hit)
			return drop(hit, bytes);
	}
	return account(XDP_PASS, bytes);
}

char LICENSE[] SEC("license") = "GPL";
