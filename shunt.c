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
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_flow.h>

#include "testpmd.h"

#define IP_DEFTTL  64   /* from RFC 1340. */

struct rte_ether_hdr streams_ether_hdr[RTE_MAX_STREAMS];
struct rte_udp_hdr streams_udp_hdr[RTE_MAX_STREAMS];
struct rte_ipv4_hdr  streams_ip_hdr[RTE_MAX_STREAMS];
uint64_t streams_sequences[RTE_MAX_STREAMS];

static inline void
copy_buf_to_pkt(void* buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset),
			buf, (size_t) len);
		return;
	}
}

static inline bool
pkt_burst_prepare(struct rte_mbuf *pkt, struct rte_mempool *mbp,
		struct rte_ether_hdr *eth_hdr, const uint16_t vlan_tci,
		const uint16_t vlan_tci_outer, const uint64_t ol_flags,
		const uint16_t idx, const struct fwd_stream *fs)
{
	rte_pktmbuf_reset_headroom(pkt);
	pkt->data_len = streams_packet_size[fs->peer_addr];
	pkt->ol_flags &= EXT_ATTACHED_MBUF;
	pkt->ol_flags |= ol_flags;
	pkt->vlan_tci = vlan_tci;
	pkt->vlan_tci_outer = vlan_tci_outer;
	pkt->l2_len = sizeof(struct rte_ether_hdr);
	pkt->l3_len = sizeof(struct rte_ipv4_hdr);

	pkt->pkt_len = pkt->data_len;
	pkt->next = NULL; 
	/*
	 * Copy headers in first packet segment(s).
	 */
	uint16_t sm_id=fs->peer_addr;
	copy_buf_to_pkt(&streams_ether_hdr[sm_id], sizeof(struct rte_ether_hdr), pkt, 0);
	copy_buf_to_pkt(&streams_ip_hdr[sm_id], sizeof(struct rte_ipv4_hdr), pkt,
			sizeof(struct rte_ether_hdr));
	
	copy_buf_to_pkt(&streams_udp_hdr[sm_id], sizeof(struct rte_udp_hdr), pkt,
			sizeof(struct rte_ether_hdr) +
			sizeof(struct rte_ipv4_hdr));

	struct packet_mark{
		uint64_t magic_num;
		uint64_t sq;
	}marker;
	marker.magic_num=rte_cpu_to_be_64(8386112020297315432l);
	marker.sq=rte_cpu_to_be_64(streams_sequences[sm_id]++);

	copy_buf_to_pkt(&marker, sizeof(marker), pkt,
			sizeof(struct rte_ether_hdr) +
			sizeof(struct rte_ipv4_hdr)+sizeof(struct rte_udp_hdr));
	/*
	 * Complete first mbuf of packet and append it to the
	 * burst of packets to be transmitted.
	 */
	pkt->nb_segs = 1;

	return true;
}

static void
pkt_burst_shunt_send(struct fwd_stream *fs)
{
	// 
	
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_port *txp;
	struct rte_mbuf *pkt;
	struct rte_mempool *mbp;
	struct rte_ether_hdr eth_hdr;
	uint16_t nb_tx;
	uint16_t nb_pkt;
	uint16_t vlan_tci, vlan_tci_outer;
	uint32_t retry;
	uint64_t ol_flags = 0;
	uint64_t tx_offloads;
	uint64_t start_tsc = 0;

	get_start_cycles(&start_tsc);

	mbp = current_fwd_lcore()->mbp;
	txp = &ports[fs->tx_port];
	tx_offloads = txp->dev_conf.txmode.offloads;
	vlan_tci = txp->tx_vlan_id;
	vlan_tci_outer = txp->tx_vlan_id_outer;
	if (tx_offloads	& DEV_TX_OFFLOAD_VLAN_INSERT)
		ol_flags = PKT_TX_VLAN_PKT;
	if (tx_offloads & DEV_TX_OFFLOAD_QINQ_INSERT)
		ol_flags |= PKT_TX_QINQ_PKT;
	if (tx_offloads & DEV_TX_OFFLOAD_MACSEC_INSERT)
		ol_flags |= PKT_TX_MACSEC;

	/*
	 * Initialize Ethernet header.
	 */
	rte_ether_addr_copy(&peer_eth_addrs[fs->peer_addr], &eth_hdr.d_addr);
	rte_ether_addr_copy(&ports[fs->tx_port].eth_addr, &eth_hdr.s_addr);
	eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	if (rte_mempool_get_bulk(mbp, (void **)pkts_burst,
				nb_pkt_per_burst) == 0) {
		for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
			if (unlikely(!pkt_burst_prepare(pkts_burst[nb_pkt], mbp,
							&eth_hdr, vlan_tci,
							vlan_tci_outer,
							ol_flags,
							nb_pkt, fs))) {
				rte_mempool_put_bulk(mbp,
						(void **)&pkts_burst[nb_pkt],
						nb_pkt_per_burst - nb_pkt);
				break;
			}
		}
	} else {
		for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
			pkt = rte_mbuf_raw_alloc(mbp);
			if (pkt == NULL)
				break;
			if (unlikely(!pkt_burst_prepare(pkt, mbp, &eth_hdr,
							vlan_tci,
							vlan_tci_outer,
							ol_flags,
							nb_pkt, fs))) {
				rte_pktmbuf_free(pkt);
				break;
			}
			pkts_burst[nb_pkt] = pkt;
		}
	}

	if (nb_pkt == 0)
		return;

	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_pkt);

	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_pkt) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_pkt && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_pkt - nb_tx);
		}
	}
	fs->tx_packets += nb_tx;


	inc_tx_burst_stats(fs, nb_tx);
	if (unlikely(nb_tx < nb_pkt)) {
		if (verbose_level > 0 && fs->fwd_dropped == 0)
			printf("port %d tx_queue %d - drop "
			       "(nb_pkt:%u - nb_tx:%u)=%u packets\n",
			       fs->tx_port, fs->tx_queue,
			       (unsigned) nb_pkt, (unsigned) nb_tx,
			       (unsigned) (nb_pkt - nb_tx));
		fs->fwd_dropped += (nb_pkt - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_pkt);
	}

	get_end_cycles(fs, start_tsc);
	
}

static int
shunt_begin(portid_t pi)
{
	uint16_t pkt_hdr_len, pkt_data_len;
	int dynf;

	pkt_hdr_len = (uint16_t)(sizeof(struct rte_ether_hdr) +
				 sizeof(struct rte_ipv4_hdr) +
				 sizeof(struct rte_udp_hdr));
	

	uint16_t sm_id=0;
	for(sm_id=0;sm_id<nb_fwd_streams;sm_id++){
		pkt_data_len = streams_packet_size[sm_id] - pkt_hdr_len;
		printf("pkt_data_len:%d pkt_len:%d  retry_enabled:%d \n",pkt_data_len,streams_packet_size[sm_id],fwd_streams[sm_id]->retry_enabled);
		uint16_t *ptr16;
		uint32_t ip_cksum;
		uint16_t pkt_len;

		/*
		* Initialize UDP header.
		*/
		pkt_len = (uint16_t) (pkt_data_len + sizeof(struct rte_udp_hdr));
		streams_udp_hdr[sm_id].src_port = rte_cpu_to_be_16(streams_src_port[sm_id]);
		streams_udp_hdr[sm_id].dst_port = rte_cpu_to_be_16(streams_dst_port[sm_id]);
		streams_udp_hdr[sm_id].dgram_len      = RTE_CPU_TO_BE_16(pkt_len);
		streams_udp_hdr[sm_id].dgram_cksum    = 0; /* No UDP checksum. */

		/*
		* Initialize IP header.
		*/
		pkt_len = (uint16_t) (pkt_len + sizeof(struct rte_ipv4_hdr));
		streams_ip_hdr[sm_id].version_ihl   = RTE_IPV4_VHL_DEF;
		streams_ip_hdr[sm_id].type_of_service   = 0;
		streams_ip_hdr[sm_id].fragment_offset = 0;
		streams_ip_hdr[sm_id].time_to_live   = IP_DEFTTL;
		streams_ip_hdr[sm_id].next_proto_id = IPPROTO_UDP;
		streams_ip_hdr[sm_id].packet_id = 0;
		streams_ip_hdr[sm_id].total_length   = RTE_CPU_TO_BE_16(pkt_len);
		streams_ip_hdr[sm_id].src_addr = rte_cpu_to_be_32(streams_src_ip_addr[sm_id]);
		streams_ip_hdr[sm_id].dst_addr = rte_cpu_to_be_32(streams_dst_ip_addr[sm_id]);

			/*
		* Compute IP header checksum.
		*/
		ptr16 = (unaligned_uint16_t*) &streams_ip_hdr[sm_id];
		ip_cksum = 0;
		ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
		ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
		ip_cksum += ptr16[4];
		ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
		ip_cksum += ptr16[8]; ip_cksum += ptr16[9];
			/*
		* Reduce 32 bit checksum to 16 bits and complement it.
		*/
		ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
			(ip_cksum & 0x0000FFFF);
		if (ip_cksum > 65535)
			ip_cksum -= 65535;
		ip_cksum = (~ip_cksum) & 0x0000FFFF;
		if (ip_cksum == 0)
			ip_cksum = 0xFFFF;
		streams_ip_hdr[sm_id].hdr_checksum = (uint16_t) ip_cksum;

			/*
		* Initialize Ethernet header.
		*/
		rte_ether_addr_copy(&streams_dst_mac_addr[sm_id], &streams_ether_hdr[sm_id].d_addr);
		if(
			streams_src_mac_addr[sm_id].addr_bytes[0]==0
			&& streams_src_mac_addr[sm_id].addr_bytes[1]==0
			&&streams_src_mac_addr[sm_id].addr_bytes[2]==0
			&&streams_src_mac_addr[sm_id].addr_bytes[3]==0
			&&streams_src_mac_addr[sm_id].addr_bytes[4]==0
			&&streams_src_mac_addr[sm_id].addr_bytes[5]==0
		)
		rte_ether_addr_copy(&ports[streams_port[sm_id]].eth_addr, &streams_ether_hdr[sm_id].s_addr);
		else{
			rte_ether_addr_copy(&streams_src_mac_addr[sm_id], &streams_ether_hdr[sm_id].s_addr);
		}
		streams_ether_hdr[sm_id].ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	}

	
	/* Make sure all settings are visible on forwarding cores.*/
	rte_wmb();
	return 0;
}

struct fwd_engine shunting_client_engine = {
	.fwd_mode_name  = "shunting",
	.port_fwd_begin = shunt_begin,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_shunt_send,
};
