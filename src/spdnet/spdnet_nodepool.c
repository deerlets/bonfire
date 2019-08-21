#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "spdnet-inl.h"

struct spdnet_nodepool {
	void *ctx;
	int water_mark;
	int nr_snode;

	struct list_head snodes;
	pthread_mutex_t snodes_lock;
	pthread_mutex_t snodes_del_lock;

	struct list_head pollins;
	struct list_head pollouts;
	struct list_head pollerrs;
	struct list_head recvmsg_timeouts;
};

static struct spdnet_node *
spdnet_nodepool_new_node(struct spdnet_nodepool *pool)
{
	assert(pool->nr_snode <= pool->water_mark);

	struct spdnet_node *snode = spdnet_node_new(pool->ctx, SPDNET_NODE);
	snode->count = 1;

	pthread_mutex_lock(&pool->snodes_lock);
	list_add(&snode->node, &pool->snodes);
	pool->nr_snode++;
	pthread_mutex_unlock(&pool->snodes_lock);
	return snode;
}

void *spdnet_nodepool_new(void *ctx, int water_mark)
{
	struct spdnet_nodepool *pool = malloc(sizeof(*pool));
	if (!pool) return NULL;
	memset(pool, 0, sizeof(*pool));

	pool->ctx = ctx;
	pool->water_mark = water_mark;
	pool->nr_snode = 0;
	INIT_LIST_HEAD(&pool->snodes);
	pthread_mutex_init(&pool->snodes_lock, NULL);
	pthread_mutex_init(&pool->snodes_del_lock, NULL);
	INIT_LIST_HEAD(&pool->pollins);
	INIT_LIST_HEAD(&pool->pollouts);
	INIT_LIST_HEAD(&pool->pollerrs);

	return pool;
}

int spdnet_nodepool_destroy(void *__pool)
{
	struct spdnet_nodepool *pool = __pool;

	struct spdnet_node *pos, *n;
	list_for_each_entry_safe(pos, n, &pool->snodes, node) {
		list_del(&pos->node);
		spdnet_node_destroy(pos);
	}
	pthread_mutex_destroy(&pool->snodes_lock);
	pthread_mutex_destroy(&pool->snodes_del_lock);

	free(pool);
	return 0;
}

void *spdnet_nodepool_find(void *__pool, const void *id, size_t len)
{
	struct spdnet_nodepool *pool = __pool;

	pthread_mutex_lock(&pool->snodes_lock);
	struct spdnet_node *pos;
	list_for_each_entry(pos, &pool->snodes, node) {
		if (len == pos->id_len && memcmp(id, pos->id, len) == 0) {
			pos->count++;
			pthread_mutex_unlock(&pool->snodes_lock);
			return pos;
		}
	}
	pthread_mutex_unlock(&pool->snodes_lock);

	return NULL;
}

void *spdnet_nodepool_get(void *__pool)
{
	struct spdnet_nodepool *pool = __pool;

	pthread_mutex_lock(&pool->snodes_lock);
	struct spdnet_node *pos;
	list_for_each_entry(pos, &pool->snodes, node) {
		if (pos->count == 0) {
			pos->count++;
			pthread_mutex_unlock(&pool->snodes_lock);
			return pos;
		}
	}
	pthread_mutex_unlock(&pool->snodes_lock);

	return spdnet_nodepool_new_node(pool);
}

void spdnet_nodepool_put(void *__pool, void *__snode)
{
	//struct spdnet_nodepool *pool = __pool;
	struct spdnet_node *snode = __snode;

	assert(snode->count >= 1);
	if (--snode->count == 0)
		snode->eof = 1;
}

void spdnet_nodepool_add(void *__pool, void *__snode)
{
	struct spdnet_nodepool *pool = __pool;
	struct spdnet_node *snode = __snode;

	pthread_mutex_lock(&pool->snodes_lock);
	list_add(&snode->node, &pool->snodes);
	pool->nr_snode++;
	pthread_mutex_unlock(&pool->snodes_lock);
}

void spdnet_nodepool_del(void *__pool, void *__snode)
{
	struct spdnet_nodepool *pool = __pool;
	struct spdnet_node *snode = __snode;

	pthread_mutex_lock(&pool->snodes_lock);
	pthread_mutex_lock(&pool->snodes_del_lock);
	list_del(&snode->node);
	pool->nr_snode--;
	pthread_mutex_unlock(&pool->snodes_del_lock);
	pthread_mutex_unlock(&pool->snodes_lock);
}

static int spdnet_nodepool_poll(struct spdnet_nodepool *pool, long timeout)
{
	// TODO: Implement pollout & pollerr
	//       use SPDNET_POLLIN, SPDNET_POLLOUT, SPDNET_POLLERR
	int rc = 0;
	int item_index = 0;
	zmq_pollitem_t *items;

	INIT_LIST_HEAD(&pool->pollins);
	INIT_LIST_HEAD(&pool->pollouts);
	INIT_LIST_HEAD(&pool->pollerrs);
	INIT_LIST_HEAD(&pool->recvmsg_timeouts);

	pthread_mutex_lock(&pool->snodes_lock);
	items = calloc(1, sizeof(struct zmq_pollitem_t) * (pool->nr_snode + 1));

	struct spdnet_node *pos, *n;
	list_for_each_entry_safe(pos, n, &pool->snodes, node) {
		if (pos->count == 0) {
			if (pool->nr_snode > pool->water_mark >> 1) {
				list_del(&pos->node);
				pool->nr_snode--;
				spdnet_node_destroy(pos);
			} else if (pos->eof) {
				int type = pos->type;
				list_del(&pos->node);
				spdnet_node_destroy(pos);
				pos = spdnet_node_new(pool->ctx, type);
				pos->count = 0;
				list_add(&pos->node, &pool->snodes);
			}
			continue;
		}

		if (pos->recvmsg_timeout && pos->recvmsg_timeout < time(NULL))
			list_add(&pos->recvmsg_timeout_node,
			         &pool->recvmsg_timeouts);
		else if (pos->count != 0) {
			items[item_index].socket = spdnet_get_socket(pos);
			items[item_index].fd = 0;
			items[item_index].events = ZMQ_POLLIN;
			items[item_index].revents = 0;
			item_index++;
			list_add_tail(&pos->pollin_node, &pool->pollins);
		}
	}
	pthread_mutex_lock(&pool->snodes_del_lock);
	pthread_mutex_unlock(&pool->snodes_lock);

	list_for_each_entry(pos, &pool->pollins, pollin_node) {
		if (pos->alive_timeout && pos->alive_timeout <= time(NULL)) {
			assert(spdnet_alive(pos) == 0);
			spdnet_set_alive(pos, pos->alive_interval);
		}
	}

	if (!item_index) {
		pthread_mutex_unlock(&pool->snodes_del_lock);
		goto finally;
	}

	rc = zmq_poll(items, item_index, timeout);
	pthread_mutex_unlock(&pool->snodes_del_lock);
	if (rc == -1 || rc == 0) {
		INIT_LIST_HEAD(&pool->pollins);
		INIT_LIST_HEAD(&pool->pollouts);
		INIT_LIST_HEAD(&pool->pollerrs);
		goto finally;
	}

	int i = 0;
	list_for_each_entry_safe(pos, n, &pool->pollins, pollin_node) {
		assert(i < item_index);
		if ((items[i].revents & ZMQ_POLLIN) == 0)
			list_del(&pos->pollin_node);
		i++;
	}

finally:
	free(items);
	return rc;
}

static void spdnet_nodepool_do_poll(struct spdnet_nodepool *pool)
{
	struct spdnet_node *pos, *n;

	list_for_each_entry_safe(pos, n, &pool->recvmsg_timeouts,
	                         recvmsg_timeout_node) {
		if (pos->recvmsg_cb) {
			spdnet_recvmsg_cb callback = pos->recvmsg_cb;
			void *arg = pos->recvmsg_arg;
			pos->recvmsg_cb = NULL;
			pos->recvmsg_arg = NULL;
			pos->recvmsg_timeout = 0;
			callback(pos, NULL, arg);
		}
	}

	list_for_each_entry_safe(pos, n, &pool->pollins, pollin_node) {
		struct spdnet_msg msg;
		spdnet_msg_init(&msg);
		spdnet_recvmsg(pos, &msg, 0);

		if (pos->recvmsg_cb) {
			// snode maybe released in callback, so do callback last
			spdnet_recvmsg_cb callback = pos->recvmsg_cb;
			void *arg = pos->recvmsg_arg;
			pos->recvmsg_cb = NULL;
			pos->recvmsg_arg = NULL;
			pos->recvmsg_timeout = 0;
			callback(pos, &msg, arg);
		} else {
			// it's our responsibility to release snode
			spdnet_nodepool_put(pool, pos);
		}

		spdnet_msg_close(&msg);
	}
}

int spdnet_nodepool_alive_count(void *__pool)
{
	struct spdnet_nodepool *pool = __pool;
	return pool->nr_snode;
}

int spdnet_nodepool_loop(void *__pool, long timeout)
{
	struct spdnet_nodepool *pool = __pool;

	if (spdnet_nodepool_poll(pool, timeout) == -1)
		return -1;

	spdnet_nodepool_do_poll(pool);
	return 0;
}
