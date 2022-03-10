/* 
    每个stream都是一个四元组(tx_port,rx_port,tx_queue,rx_queue);
    
    命令行新增
        --port_rxq=<port id>,<rxq id>
        --port_txq=<port id>,<txq id>
        未设置port_rxq或port_txq的设置成rxq和txq队列数量。不能超过dev_info.rx_max_queues
    runtime cmdline
        show stream stats all|<num>
    修改的函数
    testpmd.c/init_port_config()
    testpmd.c/rxtx_port_config()
    testpmd.c/init_fwd_streams()
    config.c/fwd_config_setup()
    testpmd.c/start_port()
    新增的函数
    config.c/streams_fwd_config_setup()
    testpmd.c/set_def_stream_ip_addrs
    testpmd.c/show_streams_stats(); 
 */
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
#endif
