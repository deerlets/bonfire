#include "spdnet.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static struct spdnet_node *
spdnet_nodepool_new_node(struct spdnet_nodepool *pool, int type)
{
	assert(pool->nr_snode <= pool->water_mark);

	struct spdnet_node *snode = malloc(sizeof(*snode));
	memset(snode, 0, sizeof(*snode));
	spdnet_node_init(snode, type, pool->ctx);
	snode->count = 1;

	mutex_lock(&pool->snodes_lock);
	list_add(&snode->node, &pool->snodes);
	pool->nr_snode++;
	mutex_unlock(&pool->snodes_lock);
	return snode;
}

int spdnet_nodepool_init(struct spdnet_nodepool *pool, int water_mark, void *ctx)
{
	memset(pool, 0, sizeof(*pool));

	pool->ctx = ctx;
	pool->water_mark = water_mark;
	pool->nr_snode = 0;
	INIT_LIST_HEAD(&pool->snodes);
	mutex_init(&pool->snodes_lock);
	mutex_init(&pool->snodes_del_lock);
	INIT_LIST_HEAD(&pool->pollins);
	INIT_LIST_HEAD(&pool->pollouts);
	INIT_LIST_HEAD(&pool->pollerrs);
	return 0;
}

int spdnet_nodepool_close(struct spdnet_nodepool *pool)
{
	struct spdnet_node *pos, *n;
	list_for_each_entry_safe(pos, n, &pool->snodes, node) {
		list_del(&pos->node);
		spdnet_node_close(pos);
		free(pos);
	}
	mutex_close(&pool->snodes_lock);
	mutex_close(&pool->snodes_del_lock);

	return 0;
}

struct spdnet_node *
spdnet_nodepool_find(struct spdnet_nodepool *pool, const char *name)
{
	mutex_lock(&pool->snodes_lock);
	struct spdnet_node *pos;
	list_for_each_entry(pos, &pool->snodes, node) {
		if (strcmp(name, pos->id) == 0) {
			pos->count++;
			mutex_unlock(&pool->snodes_lock);
			return pos;
		}
	}
	mutex_unlock(&pool->snodes_lock);

	return NULL;
}

struct spdnet_node *spdnet_nodepool_get(struct spdnet_nodepool *pool)
{
	mutex_lock(&pool->snodes_lock);
	struct spdnet_node *pos;
	list_for_each_entry(pos, &pool->snodes, node) {
		if (pos->count == 0) {
			pos->count++;
			mutex_unlock(&pool->snodes_lock);
			return pos;
		}
	}
	mutex_unlock(&pool->snodes_lock);

	return spdnet_nodepool_new_node(pool, SPDNET_NODE);
}

void spdnet_nodepool_put(struct spdnet_nodepool *pool, struct spdnet_node *snode)
{
	assert(snode->count >= 1);
	if (--snode->count == 0)
		snode->eof = 1;
}

void spdnet_nodepool_add(struct spdnet_nodepool *pool, struct spdnet_node *snode)
{
	mutex_lock(&pool->snodes_lock);
	list_add(&snode->node, &pool->snodes);
	pool->nr_snode++;
	mutex_unlock(&pool->snodes_lock);
}

void spdnet_nodepool_del(struct spdnet_nodepool *pool, struct spdnet_node *snode)
{
	mutex_lock(&pool->snodes_lock);
	mutex_lock(&pool->snodes_del_lock);
	list_del(&snode->node);
	pool->nr_snode--;
	mutex_unlock(&pool->snodes_del_lock);
	mutex_unlock(&pool->snodes_lock);
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

	mutex_lock(&pool->snodes_lock);
	items = calloc(1, sizeof(struct zmq_pollitem_t) * (pool->nr_snode + 1));

	struct spdnet_node *pos, *n;
	list_for_each_entry_safe(pos, n, &pool->snodes, node) {
		if (pos->count == 0) {
			if (pool->nr_snode > pool->water_mark >> 1) {
				list_del(&pos->node);
				pool->nr_snode--;
				spdnet_node_close(pos);
				free(pos);
			} else if (pos->eof) {
				list_del(&pos->node);
				spdnet_node_close(pos);
				spdnet_node_init(pos, pos->type, pool->ctx);
				pos->count = 0;
				list_add(&pos->node, &pool->snodes);
			}
			continue;
		}

		if (pos->recvmsg_timeout && pos->recvmsg_timeout < time(NULL))
			list_add(&pos->recvmsg_timeout_node,
			         &pool->recvmsg_timeouts);
		else if (pos->count != 0) {
			items[item_index].socket = spdnet_node_get_socket(pos);
			items[item_index].fd = 0;
			items[item_index].events = ZMQ_POLLIN;
			items[item_index].revents = 0;
			item_index++;
			list_add_tail(&pos->pollin_node, &pool->pollins);
		}
	}
	mutex_lock(&pool->snodes_del_lock);
	mutex_unlock(&pool->snodes_lock);

	list_for_each_entry(pos, &pool->pollins, pollin_node) {
		if (pos->alive_timeout && pos->alive_timeout <= time(NULL)) {
			assert(spdnet_alive(pos) == 0);
			spdnet_setalive(pos, pos->alive_interval);
		}
	}

	if (!item_index) {
		mutex_unlock(&pool->snodes_del_lock);
		goto finally;
	}

	rc = zmq_poll(items, item_index, timeout);
	mutex_unlock(&pool->snodes_del_lock);
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
			pos->recvmsg_cb = NULL;
			pos->recvmsg_timeout = 0;
			callback(pos, NULL);
		}
	}

	list_for_each_entry_safe(pos, n, &pool->pollins, pollin_node) {
		struct spdnet_msg msg;
		spdnet_msg_init(&msg);
		spdnet_recvmsg(pos, &msg, 0);

		if (pos->recvmsg_cb) {
			// snode maybe released in callback, so do callback last
			spdnet_recvmsg_cb callback = pos->recvmsg_cb;
			pos->recvmsg_cb = NULL;
			pos->recvmsg_timeout = 0;
			callback(pos, &msg);
		} else {
			// it's our responsibility to release snode
			spdnet_nodepool_put(pool, pos);
		}

		spdnet_msg_close(&msg);
	}
}

int spdnet_nodepool_loop(struct spdnet_nodepool *pool, long timeout)
{
	if (spdnet_nodepool_poll(pool, timeout) == -1)
		return -1;

	spdnet_nodepool_do_poll(pool);
	return 0;
}
