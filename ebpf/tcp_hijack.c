// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf/bpf_endian.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_parsing_helpers.h"

char __license[] SEC("license") = "GPL";

#define MAX_ENTRIES 64

struct ident_header {
  struct ethhdr ethhdr;
  struct iphdr iphdr;
  struct tcphdr tcphdr;
} __attribute__((packed));

struct bpf_map_def SEC("maps") xsks_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") qidconf_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") conntrack_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(struct ident_header),
    .max_entries = 65535,
};

// key ipv4 + port, value is any
struct bpf_map_def SEC("maps") whitelist_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = MAX_ENTRIES,
};

// 1 is server
static const __u32 server_mode = 1;

struct bpf_map_def SEC("maps") mode_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

static __always_inline __u64 get_key(__be32 ip, __be16 port) {
  __u64 key = bpf_ntohl(ip);
  key = key << 16;
  key = key | bpf_ntohs(port);
  return key;
}

static int is_tcp_packet(void *data, void *data_end, struct ethhdr **ethhdr,
                         struct iphdr **iphdr, struct tcphdr **tcphdr) {
  struct hdr_cursor nh = {.pos = data};
  int is_tcp = 0;

  // Parse Ethernet and IP/IPv6 headers
  if (parse_ethhdr(&nh, data_end, ethhdr) == -1) {
    goto out;
  }

  // Skip not IPv4 protocol
  if (bpf_htons((*ethhdr)->h_proto) != ETH_P_IP) {
    goto out;
  }

  if (parse_iphdr(&nh, data_end, iphdr) == -1) {
    goto out;
  }

  // Skip not TCP protocol
  if ((*iphdr)->protocol != IPPROTO_TCP) {
    goto out;
  }

  if (parse_tcphdr(&nh, data_end, tcphdr) == -1) {
    goto out;
  }

  is_tcp = 1;
out:
  return is_tcp;
}

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx) {
  int index = ctx->rx_queue_index;
  struct ethhdr *ethhdr;
  struct iphdr *iphdr;
  struct tcphdr *tcphdr;
  struct ident_header *ident, new_ident;
  __u32 ack;
  __u64 key, conn_key;
  __u32 action = XDP_PASS;

  if (!is_tcp_packet((void *)(long)ctx->data, (void *)(long)ctx->data_end,
                     &ethhdr, &iphdr, &tcphdr)) {
    goto out;
  }

  if (bpf_map_lookup_elem(&mode_map, &server_mode)) {
    // server mode
    key = get_key(iphdr->daddr, tcphdr->dest);
    conn_key = get_key(iphdr->saddr, tcphdr->source);
  } else {
    // client mode
    key = get_key(iphdr->saddr, tcphdr->source);
    conn_key = get_key(iphdr->daddr, tcphdr->dest);
  }

  if (!bpf_map_lookup_elem(&whitelist_map, &key)) {
    goto out;
  }

  // close connection
  if (tcphdr->rst || tcphdr->fin) {
    bpf_map_delete_elem(&conntrack_map, &conn_key);
    goto out;
  }

  ident = bpf_map_lookup_elem(&conntrack_map, &conn_key);
  if (ident) {
    ack = bpf_ntohl(tcphdr->ack_seq);
    if (ack <= bpf_ntohl(ident->tcphdr.ack_seq)) {
      goto nocopy;
    }
  }

  memcpy(&new_ident.ethhdr, ethhdr, sizeof(struct ethhdr));
  memcpy(&new_ident.iphdr, iphdr, sizeof(struct iphdr));
  memcpy(&new_ident.tcphdr, tcphdr, sizeof(struct tcphdr));
  bpf_map_update_elem(&conntrack_map, &conn_key, &new_ident, BPF_ANY);

nocopy:
  if (!tcphdr->psh) {
    goto out;
  }

#ifdef TCP_DEBUG
  bpf_printk("from %pI4:%d", &iphdr->saddr, bpf_ntohs(tcphdr->source));
  bpf_printk("to %pI4:%d", &iphdr->daddr, bpf_ntohs(tcphdr->dest));
  bpf_printk("seq: %u, ack: %u", bpf_ntohl(tcphdr->seq),
             bpf_ntohl(tcphdr->ack_seq));
#endif

  if (!bpf_map_lookup_elem(&qidconf_map, &index)) {
    goto out;
  }

  action = bpf_redirect_map(&xsks_map, index, 0);
out:
  return action;
}
