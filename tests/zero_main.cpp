#include <gtest/gtest.h>
#include "spdnet.h"
#include "task.h"
#include "service.h"
#include "utils.h"

int main(int argc, char *argv[])
{
	int rc;

	void *ctx = spdnet_ctx_create();
	struct spdnet_router router;
	spdnet_router_init(&router, "router_inner", ctx);
	spdnet_router_bind(&router, SPDNET_ROUTER_DEFAULT_ADDRESS);
	struct task router_task;
	task_init(&router_task, "router_task",
	          (task_run_func_t)spdnet_router_run, &router);
	task_start(&router_task);

	char pgm_addr[SPDNET_ADDRESS_SIZE];
	snprintf(pgm_addr, sizeof(pgm_addr), "epgm://%s;%s:%d",
	         get_ifaddr(), SPDNET_MULTICAST_DEFAULT_IP,
	         SPDNET_MULTICAST_DEFAULT_PORT);
	struct spdnet_nodepool serv_snodepool;
	struct spdnet_nodepool req_snodepool;
	struct spdnet_multicast smulticast;
	spdnet_nodepool_init(&serv_snodepool, 20, ctx);
	spdnet_nodepool_init(&req_snodepool, 20, ctx);
	spdnet_multicast_init(&smulticast, pgm_addr, 1, ctx);
	servhub_init(default_servhub(), "servhub", SPDNET_ROUTER_INNER_ADDRESS,
	             &serv_snodepool, &req_snodepool, &smulticast);
	struct task servhub_task;
	task_init(&servhub_task, "servhub_task",
	          (task_run_func_t)servhub_run, default_servhub());
	task_start(&servhub_task);

	::testing::InitGoogleTest(&argc, argv);
	rc = RUN_ALL_TESTS();

	task_stop(&router_task);
	task_close(&router_task);
	spdnet_router_close(&router);

	task_stop(&servhub_task);
	task_close(&servhub_task);
	servhub_close(default_servhub());
	spdnet_nodepool_close(&serv_snodepool);
	spdnet_nodepool_close(&req_snodepool);
	spdnet_multicast_close(&smulticast);
	spdnet_ctx_destroy(ctx);

	return rc;
}
