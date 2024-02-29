//#define KBUILD_MODNAME "filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
BPF_TABLE("hash", uint32_t, int, block_ip, 255);

int ipfilter(struct xdp_md *ctx)
{
  //bpf_trace_printk("Got a Packet\n");
  int *ip = NULL;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if ((void*)eth + sizeof(*eth) <= data_end)
  {
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)iph + sizeof(*iph) <= data_end)
    {
    	uint32_t ip_src = htonl(iph->saddr);
  	//bpf_trace_printk("source ip address is %u\n", ip_src);
  	ip = block_ip.lookup(&ip_src);
  	if(ip)
    {
  		bpf_trace_printk("the packet with source ip: %u is dropped\n", ip_src);
	 	return XDP_DROP;
    }
    }
  }
  return XDP_PASS;
}
