#ifndef __ZEBRA_LIST_H
#define __ZEBRA_LIST_H

#ifdef ZEBRA_INTERNAL
#include <extlist.h>
#define zebra_list_head list_head
#define zebra_hlist_head hlist_head
#define zebra_hlist_node hlist_node
#else
struct zebra_list_head {
	struct zebra_list_head *prev, *next;
};

struct zebra_hlist_head {
	struct zebra_hlist_node *first;
};

struct zebra_hlist_node {
	struct zebra_hlist_node *next, * *pprev;
};
#endif

#endif
