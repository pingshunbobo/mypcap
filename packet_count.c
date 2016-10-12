#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include "ip_packet.h"

#define UPLOAD 1
#define DOWNLOAD 2

struct remote_node{
	struct in_addr remote_addr;
	int upload;
	int download;
	struct remote_node *next;
}; 

struct localaddr_index{
	struct in_addr local_addr;
	int all_upload;
	int all_download;
	struct remote_node *head;
	struct remote_node *tail;
	struct localaddr_index *next;
};

struct index_table{
	struct localaddr_index *head;
	struct localaddr_index *tail;
};

struct index_table *init_count()
{
	struct index_table * table = malloc(sizeof(struct index_table));
	table->head = NULL;
	table->tail = NULL;

	return table;
};

int cleared_index()
{

	return 0;
}

int add_node(struct localaddr_index *index, struct in_addr *ip_remote,int way,int size)
{
	struct remote_node *node;
	node = index->head;
	while(node != NULL){
		if(!memcmp(node->remote_addr,ip_remote,10)){
			break;
		}
		node = node->next;
	}
	if(node == NULL){
		node = malloc(sizeof(struct remote_node));
		node->remote_addr = *ip_remote;
		node->next = NULL;
		node->download = 0;
		node->upload = 0;

		index->taili->next = node;
		index->tail = node;
	}

	if(way == DOWNLOAD)
		node->download += size;
	else
		node->upload += size;

	return 0;
}
int add_count(struct sniff_ip *ip, struct index_table *table)
{
	struct in_addr ip_local,ip_remote;
	struct localaddr_index *index;

	char home_network[]="192.168.1.0";
	int load_way;
	int load_size;

	if(!memcmp(ip->ip_src,home_network,10)){
		ip_local = ip->ip_src;
		ip_remote = ip->ip_dst;
		load_way = UPLOAD;
	}
	else{
		ip_local = ip->ip_dst;
		ip_remote = ip->ip_src;
		load_way = DOWNLOAD;
	}
	load_size = ip->ip_len;

	index = table->head;
	while(index != NULL){
		if(!memcmp(ip_local,index->local_addr,10))
			break;
		index = index->next;
	}
	if(index == NULL){
		index = malloc(sizeof(struct localaddr_index));
		index->local_addr = ip_local;
		index->all_upload = 0;
		index->all_download = 0;
		index->next=NULL;

		table->tail->next = index;
		table->tail = index; 
	}
	add_node(index,&ip_remote,load_way,load_size);

	return 0;
}

void dump_count(struct localaddr_index *index)
{

}
