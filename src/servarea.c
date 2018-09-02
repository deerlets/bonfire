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
	sa->servtab = (struct service **)calloc(1, sizeof(void *) * NR_SERVICE);
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

	service->tag = calc_tag(service->name, strlen(service->name));

	struct service *p = sa->servtab[tag_hash_fn(service->tag)];

	if (!p)
		sa->servtab[tag_hash_fn(service->tag)] = service;
	else {
		while (p->hash_next) {
			if (p == service || p->tag == service->tag)
				return;
			p = p->hash_next;
		}
		//service->hash_next = p->hash_next;
		p->hash_next = service;
		service->hash_prev = p;
	}

	list_add(&service->node, &sa->services);
}

void servarea_unregister_service(struct servarea *sa, struct service *service)
{
	assert(service->name);

	struct service *p = sa->servtab[tag_hash_fn(service->tag)];

	if (p == service)
		sa->servtab[tag_hash_fn(service->tag)] = service->hash_next;

	if (service->hash_prev)
		service->hash_prev->hash_next = service->hash_next;
	if (service->hash_next)
		service->hash_next->hash_prev = service->hash_prev;

	list_del(&service->node);
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

	struct service *p = sa->servtab[tag_hash_fn(tag)];
	for (; p != NULL; p = p->hash_next) {
		if (strcmp(p->name, name) == 0)
			return p;
	}

	return NULL;
}

struct service *
servarea_find_service(struct servarea *sa, const char *name, size_t len)
{
	unsigned int tag = calc_tag(name, len);

	struct service *p = sa->servtab[tag_hash_fn(tag)];
	for (; p != NULL; p = p->hash_next) {
		if (strlen(p->name) == len && memcmp(p->name, name, len) == 0)
			return p;
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
