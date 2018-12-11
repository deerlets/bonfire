#include "service.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#define NR_SERVICE 919
#define tag_hash_fn(tag) (tag % NR_SERVICE)

static unsigned int calc_tag(const void *buf, size_t len)
{
	unsigned int retval = ~0;
	char *tag = (char *)&retval;

	for (int i = 0; i < len; i++)
		tag[i % 4] ^= *((unsigned char *)buf + i);

	return retval;
}

int servarea_init(struct servarea *sa, const char *name)
{
	memset(sa, 0, sizeof(*sa));

	sa->name = name;
	sa->servtab = (struct hlist_head *)calloc(
		NR_SERVICE, sizeof(struct hlist_head));
	if (sa->servtab == NULL)
		return -1;

	INIT_LIST_HEAD(&sa->services);
	INIT_LIST_HEAD(&sa->node);
	return 0;
}

int servarea_close(struct servarea *sa)
{
	assert(sa->servtab);
	free(sa->servtab);

	struct service *pos, *n;
	list_for_each_entry_safe(pos, n, &sa->services, node)
		list_del(&pos->node);

	return 0;
}

void servarea_register_service(struct servarea *sa, struct service *service)
{
	assert(service->name);
	assert(service->hash_node.next == NULL);
	assert(service->hash_node.pprev == NULL);

	service->tag = calc_tag(service->name, strlen(service->name));

	struct hlist_head *head = &sa->servtab[tag_hash_fn(service->tag)];
	hlist_add_head(&service->hash_node, head);

	list_add(&service->node, &sa->services);
}

void servarea_unregister_service(struct servarea *sa, struct service *service)
{
	assert(service->name);

	hlist_del_init(&service->hash_node);
	list_del_init(&service->node);
}

void servarea_register_services(struct servarea *sa, struct service *services)
{
	while (services && services->name != NULL) {
		servarea_register_service(sa, services);
		services++;
	}
}

struct service *
__servarea_find_service(struct servarea *sa, const char *name)
{
	unsigned int tag = calc_tag(name, strlen(name));

	struct hlist_head *head = &sa->servtab[tag_hash_fn(tag)];
	struct service *pos;
	hlist_for_each_entry(pos, head, hash_node) {
		if (strcmp(pos->name, name) == 0)
			return pos;
	}

	return NULL;
}

struct service *
servarea_find_service(struct servarea *sa, const char *name, size_t len)
{
	unsigned int tag = calc_tag(name, len);

	struct hlist_head *head = &sa->servtab[tag_hash_fn(tag)];
	struct service *pos;
	hlist_for_each_entry(pos, head, hash_node) {
		if (strlen(pos->name) == len &&
		    memcmp(pos->name, name, len) == 0)
			return pos;
	}

	return NULL;
}

service_handler_func_t
__servarea_find_handler(struct servarea *sa, const char *name)
{
	struct service *p = __servarea_find_service(sa, name);
	if (p) return p->handler;
	return NULL;
}

service_handler_func_t
servarea_find_handler(struct servarea *sa, const char *name, size_t len)
{
	struct service *p = servarea_find_service(sa, name, len);
	if (p) return p->handler;
	return NULL;
}
