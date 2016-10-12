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

struct index_table *init_count();
int cleared_index();
int add_node(struct localaddr_index *index, struct in_addr *ip_remote,int way,int size);
int add_count(struct sniff_ip *ip, struct index_table *table);
void dump_count(struct localaddr_index *index);
