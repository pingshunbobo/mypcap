#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
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
	int sessions;
	int all_upload;
	int all_download;
	struct remote_node *head;
	struct remote_node *tail;
	struct localaddr_index *prev;
	struct localaddr_index *next;
};

struct index_table{
	struct localaddr_index *head;
	struct localaddr_index *tail;
};
struct index_table *counter;

struct index_table *init_count()
{
	struct index_table * table;
	table = malloc(sizeof(struct index_table));
	table->head = NULL;
	table->tail = NULL;

	return table;
};


/*
 * Sort function . sort index order by sent+recv bytes!
 */
void sort_count(struct index_table *table)
{
	int a_bytes, b_bytes;
	struct localaddr_index *a_index,*b_index;
	struct localaddr_index swap_index;
	for(a_index = table->head; a_index != NULL; a_index = a_index->next){
		a_bytes = a_index->all_upload + a_index->all_download;
		for(b_index = table->head; b_index != NULL; b_index = b_index->next){
			b_bytes = b_index->all_upload + b_index->all_download;
			if(a_bytes > b_bytes){
				//swap two index;
				swap_index = *a_index;
				a_index->local_addr = b_index->local_addr;
				a_index->head = b_index->head;
				a_index->tail = b_index->tail;
				a_index->all_download = b_index->all_download;
				a_index->all_upload = b_index->all_upload;
				
				b_index->local_addr = swap_index.local_addr;
				b_index->head = swap_index.head;
				b_index->all_download = swap_index.all_download;
				b_index->all_upload = swap_index.all_upload;
				b_index->tail = swap_index.tail;
			}
		}
	}
}

int clean_index(struct index_table *table)
{
	struct localaddr_index *index, *next_index;
        struct remote_node *node, *next_node;
        next_index = table->head;
	
	while(next_index != NULL){
		next_node = next_index->head;
		while(next_node != NULL){
			node = next_node;
			next_node = next_node->next;
			free(node);
		}
		index = next_index;
		next_index = next_index->next;
		free(index);
	}
	table->head = NULL;
	table->tail = NULL;

	return 0;
}

void dump_count(struct index_table *table)
{
	struct localaddr_index *index;
	struct remote_node *node;

	sort_count(table);
	printf(":::: begin :::\n");
	index = table->head;
        while(index != NULL){
                printf("%s \t sessions %d\t down %dk\tup %dk\n",inet_ntoa(index->local_addr),index->sessions,index->all_download/1024, index->all_upload/1024);
/*		node = index->head;
        	while(node != NULL){
			printf("\t=>%s down %d up %d\n",inet_ntoa(node->remote_addr),node->download,node->upload);
                	node = node->next;
        	}
		printf("\n");
*/		index = index->next;
        }
	printf(":::: end :::\n");
}

void sig_dump()
{
	alarm(2);
	dump_count(counter);
	clean_index(counter);
	return;
}


int add_node(struct localaddr_index *index, struct in_addr *ip_remote, int way, int size)
{
	struct remote_node *node;
	char remote_addr[15] = {0};

	node = index->head;
	strcpy(remote_addr,inet_ntoa(*ip_remote));

	while(node != NULL){
		if(!strcmp(inet_ntoa(node->remote_addr),remote_addr)){
			//printf("ADD old: %s new: %s\n",inet_ntoa(node->remote_addr),remote_addr);
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
		index->sessions += 1;
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
		index->sessions = 0;
		index->all_upload = 0;
		index->all_download = 0;
		index->prev = table->tail;
		index->next = NULL;
		if(table->head == NULL)
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
	return 0;
}


/*
 * singnal control dump data.
 */

void addsig( int sig, void( handler )(int), bool restart)
{
	struct sigaction sa;
	memset( &sa, '\0', sizeof( sa ) );
	sa.sa_handler = handler;
	if( restart ){
		sa.sa_flags |= SA_RESTART;
	}
	sigfillset( &sa.sa_mask );
	if(sigaction( sig, &sa, NULL ) <= -1){
		perror("sigaction");
	}
}

