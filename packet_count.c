#include <stdio.h>
#include <string.h>
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
	struct index_table * table;
	table = malloc(sizeof(struct index_table));
	table->head = NULL;
	table->tail = NULL;

	return table;
};

void dump_count(struct index_table *table)
{
	struct localaddr_index *index;
	struct remote_node *node;
	index = table->head;
        while(index != NULL){
                printf("%s \t down %d \t up %d\n",inet_ntoa(index->local_addr),index->all_download, index->all_upload);
		node = index->head;
        	while(node != NULL){
			printf("\t=>%s down %d up %d",inet_ntoa(node->remote_addr),node->download,node->upload);
                	node = node->next;
        	}
		printf("\n\n");
		index = index->next;
        }	
}

int cleared_index()
{

	return 0;
}

int add_node(struct localaddr_index *index, struct in_addr *ip_remote, int way, int size)
{
	struct remote_node *node;

	printf("readdr %s\n",inet_ntoa(*ip_remote));
	node = index->head;
	while(node != NULL){
		if(!strcmp(inet_ntoa(node->remote_addr),inet_ntoa(*ip_remote))){
			printf("ADD old: %s new: %s\n",inet_ntoa(node->remote_addr),inet_ntoa(*ip_remote));
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

		if(index->head != NULL)
			index->tail->next = node;
		else
			index->head = node;
		index->tail = node;
	}

	if(way == DOWNLOAD)
		node->download += size;
	else
		node->upload += size;
	return 0;
}
int add_count(const struct sniff_ip *ip, struct index_table *table)
{
	struct in_addr ip_local,ip_remote;
	struct localaddr_index *index;

	char home_network[]="192.168.21.0";
	int load_way;
	int load_size;

	if(!strncmp(home_network, inet_ntoa(ip->ip_src),7)){
		ip_local = ip->ip_src;
		ip_remote = ip->ip_dst;
		load_way = UPLOAD;
	}else if(!strncmp(home_network,inet_ntoa(ip->ip_dst),7)){
		ip_local = ip->ip_dst;
		ip_remote = ip->ip_src;
		load_way = DOWNLOAD;
	}else{
		printf("no src dst\n");
	}
	load_size = ip->ip_len;

	index = table->head;
	while(index != NULL){
		if(!memcmp(&ip_local,&index->local_addr,4))
			break;
		index = index->next;
	}
	if(index == NULL){
		index = malloc(sizeof(struct localaddr_index));
		index->local_addr = ip_local;
		index->head = NULL;
		index->tail = NULL;
		index->all_upload = 0;
		index->all_download = 0;
		index->next = NULL;
		if(table -> head == NULL)
			table->head = index;
		else
			table->tail->next = index;
		table->tail = index;
	}
	if(load_way == DOWNLOAD)
		index->all_download += load_size;
	else
		index->all_upload += load_size;

	add_node(index,&ip_remote,load_way,load_size);
	dump_count(table);
	return 0;
}
