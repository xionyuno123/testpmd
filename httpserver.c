

#include <microhttpd.h>
#include <jansson.h>
#include "streams.h"

#define EDGE_NUM 6
#define LINK_NUM 4

static uint32_t edges[EDGE_NUM][LINK_NUM]={
    {192<<24|168<<16|85<<8|10,192<<24|168<<16|86<<8|10,192<<24|168<<16|87<<8|10,192<<24|168<<16|88<<8|10}, // wifi 4G
    {192<<24|168<<16|81<<8|10,0,0,0}, // 太赫兹20G
    {192<<24|168<<16|81<<8|11,192<<24|168<<16|81<<8|13,0,0}, // 大流量业务01 80G
    {192<<24|168<<16|82<<8|10,192<<24|168<<16|82<<8|12,192<<24|168<<16|82<<8|13,0}, //大流量业务02, 100G
    {192<<24|168<<16|83<<8|10,192<<24|168<<16|83<<8|30,0,0}, //大流量业务03, 100G
    {192<<24|168<<16|84<<8|10,192<<24|168<<16|84<<8|30,0,0}, //大流量业务04，96G  
};
static uint8_t table[256] = 
    { 
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8, 
}; 
static inline uint16_t bits_counts(uint64_t value){
        return 
         table[value & 0xff] 
        +table[(value>>8) & 0xff]
        +table[(value>>16) & 0xff]
        +table[(value>>24) & 0xff]
        +table[(value>>32) & 0xff]
        +table[(value>>40) & 0xff]
        +table[(value>>48) & 0xff]
        +table[(value>>56) & 0xff];
}




#define NS_PER_SEC 1E9

struct MHD_Daemon *Httpddaemon;
int get_argument_iterator(void *cls,
                         enum MHD_ValueKind kind,
                         const char *key,
                         const char *value)
{
    struct timespec cur_time;

    json_t **resjson=(json_t **)(cls);
    
    
    uint64_t diff_ns,diff_rx_pkts,diff_ts_pkts,diff_bytes,diff_rx_miss;
    double bps,miss;
    static uint64_t stream_prev_ns[RTE_MAX_STREAMS];
    static uint64_t stream_prev_rx_pkts[RTE_MAX_STREAMS];
    static uint64_t stream_prev_tx_pkts[RTE_MAX_STREAMS];
    static uint64_t prev_video_rx_bytes=0;
    static uint64_t prev_video_ns=0;
    if (strcmp(key,"edge")==0){
        int sm_id,edge;
        json_t *arr=json_array();

        for(edge=0;edge<EDGE_NUM;edge++){
            int link;
            json_t * obj=json_object();
            json_object_set_new(obj,"code",json_array());
            json_object_set_new(obj,"description",json_array());
            json_object_set_new(obj,"port",json_array());
            json_object_set_new(obj,"rt_bps",json_array());
            json_object_set_new(obj,"rt_miss",json_array());
            json_object_set_new(obj,"rt_miss_pkt",json_array());
            json_object_set_new(obj,"rt_total_pkt",json_array());
            json_object_set_new(obj,"src_ip",json_array());
            json_object_set_new(obj,"dst_ip",json_array());
            for(link=0;link<LINK_NUM;link++)
            {
                uint32_t src_ip=edges[edge][link];

                if (src_ip==0) {
                    json_array_append(json_object_get(obj,"code"),json_integer(1));
                    json_array_append(json_object_get(obj,"description"),json_string("Link is Down"));
                    json_array_append(json_object_get(obj,"port"),json_integer(-1));
                    json_array_append(json_object_get(obj,"rt_bps"),json_real(0.0));
                    json_array_append(json_object_get(obj,"rt_miss"),json_real(0.0));
                    json_array_append(json_object_get(obj,"rt_miss_pkt"),json_integer(0));
                    json_array_append(json_object_get(obj,"rt_total_pkt"),json_integer(0));
                    json_array_append(json_object_get(obj,"src_ip"),json_integer(0));
                    json_array_append(json_object_get(obj,"dst_ip"),json_integer(0));
                }
                else{
                    bool find=false;
                    for(sm_id=0;sm_id<RTE_MAX_STREAMS;sm_id++){
                        if(aggre_streams_stats[sm_id].status==0)
                            continue;
                        struct hash_key* key=&(aggre_streams_stats[sm_id].key);
                        uint32_t src_ip_addr=rte_be_to_cpu_32(key->src_ip_addr);
                        uint32_t dst_ip_addr=rte_be_to_cpu_32(key->dst_ip_addr);
                        if (src_ip_addr==src_ip) {
                            find=true;
                            // static and append
                            json_array_append(json_object_get(obj,"code"),json_integer(0));
                            json_array_append(json_object_get(obj,"description"),json_string("Link is Up"));
                            json_array_append(json_object_get(obj,"port"),json_integer(0));
                            if (clock_gettime(CLOCK_MONOTONIC, &cur_time) == 0){
                                uint64_t ns=0;
		                         ns = cur_time.tv_sec * NS_PER_SEC;
		                        ns += cur_time.tv_nsec;

		                         if (stream_prev_ns[sm_id] != 0)
			                    diff_ns = ns - stream_prev_ns[sm_id];
		                        stream_prev_ns[sm_id] = ns;
                            }
                             diff_rx_pkts = (aggre_streams_stats[sm_id].rx_pkts > stream_prev_rx_pkts[sm_id])?(aggre_streams_stats[sm_id].rx_pkts - stream_prev_rx_pkts[sm_id]):0;
                             stream_prev_rx_pkts[sm_id]=aggre_streams_stats[sm_id].rx_pkts;
                            diff_ts_pkts = (aggre_streams_stats[sm_id].max_sq > stream_prev_tx_pkts[sm_id])?(aggre_streams_stats[sm_id].max_sq - stream_prev_tx_pkts[sm_id]):0;
                             stream_prev_tx_pkts[sm_id]=aggre_streams_stats[sm_id].max_sq;
                             diff_bytes=diff_rx_pkts*aggre_streams_stats[sm_id].pkt_sz;
            

                            diff_rx_miss=(diff_ts_pkts>diff_rx_pkts)?(diff_ts_pkts-diff_rx_pkts):0;
                            bps=diff_ns >0 ?((double)diff_bytes / diff_ns * NS_PER_SEC):0.0000;
                            miss= (diff_ts_pkts !=0 )? (double)diff_rx_miss/diff_ts_pkts:0.00;
                          
                            json_array_append(json_object_get(obj,"rt_bps"),json_real(bps*8));
                            json_array_append(json_object_get(obj,"rt_miss"),json_real(miss));
                            json_array_append(json_object_get(obj,"rt_miss_pkt"),json_integer(diff_rx_miss));
                            json_array_append(json_object_get(obj,"rt_total_pkt"),json_integer(diff_ts_pkts));
                            json_array_append(json_object_get(obj,"src_ip"),json_integer(src_ip_addr));
                            json_array_append(json_object_get(obj,"dst_ip"),json_integer(dst_ip_addr));

                            break;
                        }
                    }

                    if(!find){
                        json_array_append(json_object_get(obj,"code"),json_integer(1));
                        json_array_append(json_object_get(obj,"description"),json_string("Link is Down"));
                        json_array_append(json_object_get(obj,"port"),json_integer(-1));
                        json_array_append(json_object_get(obj,"rt_bps"),json_real(0.0));
                        json_array_append(json_object_get(obj,"rt_miss"),json_real(0.0));
                        json_array_append(json_object_get(obj,"rt_miss_pkt"),json_integer(0));
                        json_array_append(json_object_get(obj,"rt_total_pkt"),json_integer(0));
                        json_array_append(json_object_get(obj,"src_ip"),json_integer(0));
                        json_array_append(json_object_get(obj,"dst_ip"),json_integer(0));
                    }

                }
            }

            json_array_append(arr,obj);
        }

        /* for(sm_id=0;sm_id<RTE_MAX_STREAMS;sm_id++){
            if(aggre_streams_stats[sm_id].status==0)
                continue;
            struct hash_key* key=&(aggre_streams_stats[sm_id].key);
            json_t *obj=json_object();
            char buf[30];
            uint32_t ip_addr=rte_be_to_cpu_32(key->src_ip_addr);
            sprintf(buf,"%u.%u.%u.%u",ip_addr>>24,ip_addr>>16&0xff,ip_addr>>8&0xff,ip_addr&0xff);
            json_object_set_new(obj,"ipv4_src_addr",json_string(buf));
            ip_addr=rte_be_to_cpu_32(key->dst_ip_addr);
            sprintf(buf,"%u.%u.%u.%u",ip_addr>>24,ip_addr>>16&0xff,ip_addr>>8&0xff,ip_addr&0xff);
            json_object_set_new(obj,"ipv4_dst_addr",json_string(buf));

            json_object_set_new(obj,"dst_port",json_integer(key->dst_port));
            json_object_set_new(obj,"src_port",json_integer(key->src_port));

            json_object_set_new(obj,"l3_ptype",json_string("udp"));

            sprintf(buf,"%2x:%2x:%2x:%2x:%2x:%2x",key->dst_mac_addr.addr_bytes[0],key->dst_mac_addr.addr_bytes[1],key->dst_mac_addr.addr_bytes[2],key->dst_mac_addr.addr_bytes[3],key->dst_mac_addr.addr_bytes[4],key->dst_mac_addr.addr_bytes[5]);
            json_object_set_new(obj,"dst_mac_addr",json_string(buf));
            sprintf(buf,"%2x:%2x:%2x:%2x:%2x:%2x",key->src_mac_addr.addr_bytes[0],key->src_mac_addr.addr_bytes[1],key->src_mac_addr.addr_bytes[2],key->src_mac_addr.addr_bytes[3],key->src_mac_addr.addr_bytes[4],key->src_mac_addr.addr_bytes[5]);
            json_object_set_new(obj,"src_mac_addr",json_string(buf));

            if (clock_gettime(CLOCK_MONOTONIC, &cur_time) == 0){
                    uint64_t ns=0;
		            ns = cur_time.tv_sec * NS_PER_SEC;
		            ns += cur_time.tv_nsec;

		            if (stream_prev_ns[sm_id] != 0)
			        diff_ns = ns - stream_prev_ns[sm_id];
		            stream_prev_ns[sm_id] = ns;
            }
            diff_rx_pkts = (aggre_streams_stats[sm_id].rx_pkts > stream_prev_rx_pkts[sm_id])?(aggre_streams_stats[sm_id].rx_pkts - stream_prev_rx_pkts[sm_id]):0;
            stream_prev_rx_pkts[sm_id]=aggre_streams_stats[sm_id].rx_pkts;
            diff_ts_pkts = (aggre_streams_stats[sm_id].max_sq > stream_prev_tx_pkts[sm_id])?(aggre_streams_stats[sm_id].max_sq - stream_prev_tx_pkts[sm_id]):0;
            stream_prev_tx_pkts[sm_id]=aggre_streams_stats[sm_id].max_sq;
            diff_bytes=diff_rx_pkts*aggre_streams_stats[sm_id].pkt_sz;
            

            diff_rx_miss=(diff_ts_pkts>diff_rx_pkts)?(diff_ts_pkts-diff_rx_pkts):0;
            bps=diff_ns >0 ?((double)diff_bytes / diff_ns * NS_PER_SEC):0.0000;
            miss= (diff_ts_pkts !=0 )? (double)diff_rx_miss/diff_ts_pkts:0.00;

            json_object_set_new(obj,"bps",json_real(bps*8));
            //printf("bps: %lf\n",bps);
            json_object_set_new(obj,"miss",json_real(miss));
            json_object_set_new(obj,"diff_rx_miss",json_integer(diff_rx_miss));
            json_object_set_new(obj,"diff_ts_pkts",json_integer(diff_ts_pkts));

            json_array_append(arr,obj);
        } */

        json_object_set_new(*resjson,"edges",arr);
    }
    
    else if (strcmp(key,"videoid")==0)
    {

        uint16_t port=*(uint16_t* )value;
        udp_dst_port=port;


        json_object_set_new(*resjson,"code",json_integer(1));
    }
    else if(strcmp(key,"video")==0){
        uint64_t count=0;
        

    
        int i=0;
        for(i=0;i<1024;++i){
            count+=bits_counts(video_map[i]);
        }
        
        for(i=0;i<1024;++i){
            count+=bits_counts(video_map[i]);
        }
        
        json_object_set_new(*resjson,"num_of_video",json_integer(count));
        
        if (clock_gettime(CLOCK_MONOTONIC, &cur_time) == 0){
            uint64_t ns=0;
		    ns = cur_time.tv_sec * NS_PER_SEC;
		    ns += cur_time.tv_nsec;

		    if (prev_video_ns != 0)
			  diff_ns = ns - prev_video_ns;
		    prev_video_ns = ns;
        }
        uint64_t rx_bytes=0;
        for(i=0;i<RTE_MAX_ETHPORTS;++i){
            rx_bytes+=video_rx_bytes[i];
        }
        diff_bytes=rx_bytes>prev_video_rx_bytes ? rx_bytes-prev_video_rx_bytes : 0;
        prev_video_rx_bytes=rx_bytes;
        bps=diff_ns >0 ?((double)diff_bytes / diff_ns * NS_PER_SEC):0.0000;

        json_object_set_new(*resjson,"bps",json_real(bps*8));
        printf("bps: %lf  count: %ld \n", bps*8, count);
        json_object_set_new(*resjson,"current_videoid",json_integer(udp_dst_port));
    }
}

static int answer_for_response(void *cls,
                              struct MHD_Connection *connection,
                              const char *url,
                              const char *method,
                              const char *version,
                              const char *upload_data,
                              size_t *upload_data_size,
                              void **con_cls)
{
    int ret=0;
    if(strcmp(method,MHD_HTTP_METHOD_GET)==0){
        json_t * resjson=json_object();
        MHD_get_connection_values(connection,MHD_GET_ARGUMENT_KIND,&get_argument_iterator,&resjson);
        size_t size=json_dumpb(resjson,NULL,0,0);
        char * buffer=json_dumps(resjson,JSON_ENSURE_ASCII);
        struct MHD_Response* response=MHD_create_response_from_buffer(size,buffer,MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(response,MHD_HTTP_HEADER_CONTENT_TYPE,"application/json");
        ret=MHD_queue_response(connection,MHD_HTTP_OK,response);
        MHD_destroy_response(response);
        //printf("request is addressing\n");
        return ret;

    }else{
        int ret=MHD_queue_response(connection,MHD_HTTP_NOT_IMPLEMENTED,NULL);
        return ret;
    }
}




void httpserver_start(){
    Httpddaemon=MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD|MHD_USE_EPOLL,80,NULL,NULL,&answer_for_response,NULL,MHD_OPTION_END);
    if(Httpddaemon==NULL){
        printf("daemon failed to start\n");
        return ;
    }
    else{
        printf("deamon start\n");
        return ;
    }
}
void httpd_server_stop(){
    MHD_stop_daemon(Httpddaemon);
    return;
}
