#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "spdnet-inl.h"

struct spdnet_pool *spdnet_pool_new(struct spdnet_ctx *ctx, int water_mark)
{
	struct spdnet_pool *pool = malloc(sizeof(*pool));
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

void spdnet_pool_destroy(struct spdnet_pool *pool)
{
	struct spdnet_node *pos, *n;
	list_for_each_entry_safe(pos, n, &pool->snodes, node) {
		assert(pos->used == 0);
		spdnet_node_destroy(pos);
	}
	pthread_mutex_destroy(&pool->snodes_lock);
	pthread_mutex_destroy(&pool->snodes_del_lock);

	free(pool);
}

void spdnet_pool_add(struct spdnet_pool *pool, struct spdnet_node *snode)
{
	pthread_mutex_lock(&pool->snodes_lock);
	assert(snode->used == 0);
	snode->used = 0;
	snode->used = 1;
	list_add(&snode->node, &pool->snodes);
	pool->nr_snode++;
	pthread_mutex_unlock(&pool->snodes_lock);
}

void spdnet_pool_del(struct spdnet_pool *pool, struct spdnet_node *snode)
{
	pthread_mutex_lock(&pool->snodes_lock);
	pthread_mutex_lock(&pool->snodes_del_lock);
	assert(snode->used == 1);
	snode->used = 0;
	list_del(&snode->node);
	pool->nr_snode--;
	pthread_mutex_unlock(&pool->snodes_del_lock);
	pthread_mutex_unlock(&pool->snodes_lock);
}

void *spdnet_pool_get(struct spdnet_pool *pool, int type)
{
	pthread_mutex_lock(&pool->snodes_lock);
	struct spdnet_node *pos;
	list_for_each_entry(pos, &pool->snodes, node) {
		if (pos->used == 0 && pos->type == type) {
			pos->used = 1;
			pthread_mutex_unlock(&pool->snodes_lock);
			return pos;
		}
	}
	pthread_mutex_unlock(&pool->snodes_lock);

	return NULL;
}

void spdnet_pool_put(struct spdnet_pool *pool, struct spdnet_node *snode)
{
	pthread_mutex_lock(&pool->snodes_lock);
	pthread_mutex_lock(&pool->snodes_del_lock);
	assert(snode->used == 1);
	snode->used = 0;
	if (snode->is_connect)
		spdnet_disconnect(snode);
	if (snode->is_bind)
		spdnet_unbind(snode);
	pthread_mutex_unlock(&pool->snodes_del_lock);
	pthread_mutex_unlock(&pool->snodes_lock);
}

static int spdnet_pool_poll(struct spdnet_pool *pool, long timeout)
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
		if (!pos->used || !pos->recvmsg_cb ||
		    (!pos->is_bind && !pos->is_connect))
			continue;

		if (pos->recvmsg_timeout && pos->recvmsg_timeout < time(NULL)) {
			list_add(&pos->recvmsg_timeout_node,
			         &pool->recvmsg_timeouts);
		} else {
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

static void spdnet_pool_do_poll(struct spdnet_pool *pool)
{
	struct spdnet_node *pos, *n;

	list_for_each_entry_safe(pos, n, &pool->recvmsg_timeouts,
	                         recvmsg_timeout_node) {
		spdnet_recvmsg_cb callback = pos->recvmsg_cb;
		void *arg = pos->recvmsg_arg;
		pos->recvmsg_cb = NULL;
		pos->recvmsg_arg = NULL;
		pos->recvmsg_timeout = 0;
		callback(pos, NULL, arg);
	}

	list_for_each_entry_safe(pos, n, &pool->pollins, pollin_node) {
		struct spdnet_msg msg;
		spdnet_msg_init(&msg);
		spdnet_recvmsg(pos, &msg, 0);

		// snode maybe released in callback, so do callback last
		spdnet_recvmsg_cb callback = pos->recvmsg_cb;
		void *arg = pos->recvmsg_arg;
		pos->recvmsg_cb = NULL;
		pos->recvmsg_arg = NULL;
		pos->recvmsg_timeout = 0;
		callback(pos, &msg, arg);

		spdnet_msg_close(&msg);
	}
}

int spdnet_pool_alive_count(struct spdnet_pool *pool)
{
	return pool->nr_snode;
}

int spdnet_pool_loop(struct spdnet_pool *pool, long timeout)
{
	if (spdnet_pool_poll(pool, timeout) == -1)
		return -1;

	spdnet_pool_do_poll(pool);
	return 0;
}
