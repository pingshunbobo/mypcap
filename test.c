#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "packet_count.h"

int main()
{
	struct in_addr readdr1;
	struct in_addr readdr2;
	struct in_addr readdr3;
	struct in_addr readdr4;
	struct localaddr_index demo_index;

        demo_index.all_upload = 0;
        demo_index.all_download = 0;
        demo_index.head = NULL;
        demo_index.tail = NULL;
        demo_index.next = NULL;

	inet_aton("192.168.1.123",&demo_index.local_addr);
	inet_aton("192.168.1.21",&readdr1);
	inet_aton("192.168.1.22",&readdr2);
	inet_aton("192.168.1.23",&readdr3);
	inet_aton("192.168.1.24",&readdr4);

	printf("%s",inet_ntoa(readdr1));
	printf("%s",inet_ntoa(readdr2));
	printf("%s",inet_ntoa(readdr3));
	printf("%s",inet_ntoa(readdr4));

	add_node(&demo_index,&readdr1,1,1024);
	add_node(&demo_index,&readdr2,1,1024);
	add_node(&demo_index,&readdr3,1,1024);
	add_node(&demo_index,&readdr4,1,1024);
	
	struct remote_node *node;
	node = demo_index.head;
	while(node != NULL){
		printf("\t=>%s down %d up %d\n",inet_ntoa(node->remote_addr),node->download,node->upload);
		node = node->next;
	}
	printf("\n");
	return 0;
}
