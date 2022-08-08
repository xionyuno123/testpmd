
#ifndef _STREAMS_H
#define _STREAMS_H
#include<rte_ether.h>
uint16_t port_rxq[RTE_MAX_ETHPORTS];
uint16_t port_txq[RTE_MAX_ETHPORTS];

uint16_t nb_fwd_streams; 

bool split_streams_enabled;
bool aggregation_enabled;

#define RTE_MAX_STREAMS 64
// read from config files
uint32_t streams_src_ip_addr[RTE_MAX_STREAMS];
uint32_t streams_dst_ip_addr[RTE_MAX_STREAMS];
uint16_t streams_dst_port[RTE_MAX_STREAMS];
uint16_t streams_src_port[RTE_MAX_STREAMS];
uint32_t streams_speed[RTE_MAX_STREAMS];
size_t streams_packet_size[RTE_MAX_STREAMS];
uint16_t streams_port[RTE_MAX_STREAMS];
uint64_t streams_tics_space[RTE_MAX_STREAMS];

struct rte_ether_addr streams_src_mac_addr[RTE_MAX_STREAMS];
struct rte_ether_addr streams_dst_mac_addr[RTE_MAX_STREAMS];

void clear_stream_stats_all();
void show_stream_stats_all();
void clear_stream_stats(uint16_t sm_id);
void show_stream_stats(uint16_t sm_id);


struct hash_key{
    uint32_t src_ip_addr;
    uint32_t dst_ip_addr;
    uint16_t src_port;
    uint16_t dst_port;
    struct rte_ether_addr src_mac_addr;
    struct rte_ether_addr dst_mac_addr;
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
bool httpserver_enabled;
extern rte_spinlock_t video_spinlock;
extern volatile uint16_t udp_dst_port;
extern uint64_t video_map[1024];
extern uint64_t video_rx_pkts[RTE_MAX_ETHPORTS];
extern uint64_t video_rx_bytes[RTE_MAX_ETHPORTS];
#define HASH_INITVAL 0x7135efee
#endif
