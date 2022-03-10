/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_jhash.h>
#include "testpmd.h"

struct hash_key{
    uint32_t src_ip_addr;
    uint32_t dst_ip_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t src_mac_addr[6];
    uint8_t dst_mac_addr[6];
};

struct hash_data{
    struct hash_key key;
    uint32_t hash_value;
    uint64_t max_sq;
    uint64_t rx_pkts;
    uint16_t pkt_sz;
    bool status; // 0 UNUSED 1 USING 
    rte_spinlock_t spinlock;
};

struct packet_marker{
    uint64_t magic_num;
    uint64_t sq;
};

struct hash_data aggre_streams_stats[RTE_MAX_STREAMS];

#define HASH_INITVAL 0x7135efee

/*
    Return
        >=0 SUCCESS, return the position of aggre_streams_stats
        -1 Failed to insert (FULL or EXSITING)
*/
static int insert_hash_table(struct hash_key *key){
    int di;
    int pos=0;
    for(di=0;di<RTE_MAX_STREAMS;di++){
        uint32_t hash_value=rte_jhash(key,sizeof(struct hash_key),HASH_INITVAL);
        pos=(hash_value+di)%RTE_MAX_STREAMS;
        if(rte_atomic16_cmpset(&(aggre_streams_stats[pos].status),false,true)!=0){
            aggre_streams_stats[pos].hash_value=hash_value;
            memcpy(&(aggre_streams_stats[pos].key),key,sizeof(struct hash_key));
            return pos;
        }
        else if(aggre_streams_stats[pos].hash_value==hash_value){
            return pos;
        }
        else{
            pos=-1;
        }
    }
    
    return pos;
}





/*
 * Received a burst of packets.
 */
static void
aggregation_burst_receive(struct fwd_stream *fs)
{
	struct rte_mbuf  *pkts_burst[MAX_PKT_BURST];
	uint16_t nb_rx;
	uint16_t i;
	uint64_t start_tsc = 0;

	

	/*
	 * Receive a burst of packets.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, pkts_burst,
				 nb_pkt_per_burst);
	
	if (unlikely(nb_rx == 0))
		return;


	for (i = 0; i < nb_rx; i++)
	{
        struct rte_ether_hdr* ether_hdr=rte_pktmbuf_mtod_offset(pkts_burst[i],struct rte_ether_hdr*,0);
        struct rte_ipv4_hdr* ipv4_hdr=rte_pktmbuf_mtod_offset(pkts_burst[i],struct rte_ipv4_hdr*,sizeof(struct rte_ether_hdr));
        struct rte_udp_hdr* udp_hdr=rte_pktmbuf_mtod_offset(pkts_burst[i],struct rte_ipv4_hdr*,sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv4_hdr));
        struct packet_marker* maker=rte_pktmbuf_mtod_offset(pkts_burst[i],struct packet_marker*,sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv4_hdr)+sizeof(struct rte_udp_hdr));
        uint16_t pkt_size=pkts_burst[i]->data_len;
        uint64_t max_sq=rte_be_to_cpu_64(maker->sq);

        if(maker->magic_num == rte_cpu_to_be_64(8386112020297315432l)){
            struct hash_key key;
            key.dst_ip_addr=ipv4_hdr->dst_addr;
            key.src_ip_addr=ipv4_hdr->src_addr;
            key.dst_port=udp_hdr->dst_port;
            key.src_port=udp_hdr->src_port;
            memcpy(&(key.dst_mac_addr),&(ether_hdr->d_addr),6);
            memcpy(&(key.src_mac_addr),&(ether_hdr->s_addr),6);

            int pos=insert_hash_table(&key);
            if(pos==-1){
                perror("Received stream exceed than the RTE_MAX_STREAMS\n");
                continue;
            }
            rte_spinlock_lock(&(aggre_streams_stats[pos].spinlock));
            aggre_streams_stats[pos].max_sq=RTE_MAX(aggre_streams_stats[pos].max_sq,max_sq);
            aggre_streams_stats[pos].rx_pkts++;
            aggre_streams_stats[pos].pkt_sz;
            rte_spinlock_unlock(&(aggre_streams_stats[pos].spinlock));
        }
        rte_pktmbuf_free(pkts_burst[i]);
    }

	
}

static void aggregation_begin(uint16_t lc){
    memset(aggre_streams_stats,0,sizeof(struct hash_data)*RTE_MAX_STREAMS);
}

static void aggregation_end(uint16_t lc){

}

struct fwd_engine aggregation_engine = {
	.fwd_mode_name  = "aggre",
	.port_fwd_begin = aggregation_begin,
	.port_fwd_end   = NULL,
	.packet_fwd     = aggregation_burst_receive,
};
