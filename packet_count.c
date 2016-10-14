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
        //date;
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
	struct index_table *index = malloc(sizeof(struct index_table));
	index->head = NULL;
	index->tail = NULL;

	return index;
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
		if((node->remote_addr & *ip_remote) == *ip_remote){
			break;
		}
		node = node->next;
	}
	if(node == NULL){
		struct remote_node *new_node = malloc(sizeof(struct remote_node));
		new_node->remote_addr = *ip_remote;
		new_node->next = NULL;
		index->tail -> next = new_node;
		index->tail = new_node;	
	}

}
int add_count(struct sniff_ip *ip, struct index_table *table)
{
	struct in_addr ip_local,ip_remote;
	struct localaddr_index *index;

	char home_network[]="192.168.1.0";
	int load_way;
	int load_size;

	if(match_addr()){
		ip_local = ip->ip_src;
		load_way = UPLOAD;
	}
	else{
		ip_remote = ip->ip_dst;
		load_way = DOWNLOAD;
	}
	load_size = ip->ip_len;

	index = table->head;
	while(index != NULL){
		if(ip_local  == index->local_addr){
			add_node(index,&ip_remote,load_way,load_size);
			break;
		}
		index = index->next;
	}
	if(index == NULL){
		struct localaddr_index *new_index;
		new_index = malloc(sizeof(struct localaddr_index));
		new_index->local_addr = ip_local;
		new_index->all_upload = 0;
		new_index->all_download = 0;

		add_node(new_index,&ip_remote,load_way,load_size);
		table->tail = new_index; 
	}
	return 0;
}

void dump_count(struct localaddr_index *index)
{

}
