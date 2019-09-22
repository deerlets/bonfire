#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <node_api.h>
#include <uv.h>
#include <bonfire.h>
#include <task.h>
#include <string>
#include <list>
#include <map>

#define _ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define DECLARE_NAPI_METHOD(name, method) \
	{ name, NULL, method, NULL, NULL, NULL, napi_default, NULL }

struct service_struct {
	std::string header;
	napi_env env;
	napi_value this_obj;
	napi_ref func_ref;
	std::list<struct bmsg *> reqs;
};

struct servcall_struct {
	napi_env env;
	napi_deferred deferred;
	std::string resp;
};

struct subscribe_struct {
	std::string topic;
	napi_env env;
	napi_value this_obj;
	napi_ref func_ref;
	std::list<std::string> resps;
};

struct binding {
	uv_async_t service_async;
	std::map<std::string, service_struct *> service_list;
	pthread_mutex_t service_lock;

	uv_async_t servcall_async;
	std::list<servcall_struct *> servcall_list;
	pthread_mutex_t servcall_lock;

	uv_async_t subscribe_async;
	std::map<std::string, subscribe_struct *> subscribe_list;
	pthread_mutex_t subscribe_lock;

	struct task *t;
};

static void service_async_cb(uv_async_t *handle)
{
	binding *bd = (binding *)uv_handle_get_data((uv_handle_t *)handle);

	pthread_mutex_lock(&bd->service_lock);

	for (auto &item : bd->service_list) {
		napi_env env = item.second->env;
		napi_value this_obj = item.second->this_obj;
		napi_ref func_ref = item.second->func_ref;

		napi_handle_scope scope;
		napi_open_handle_scope(env, &scope);

		napi_async_context context;
		napi_value serva;
		napi_create_string_utf8(env, "serva", NAPI_AUTO_LENGTH, &serva);
		napi_async_init(env, nullptr, serva, &context);

		napi_callback_scope cb_scope;
		napi_open_callback_scope(env, nullptr, context, &cb_scope);

		napi_value func;
		napi_get_reference_value(env, func_ref, &func);

		for (auto &bm : item.second->reqs) {
			void *content;
			size_t size;
			bmsg_get_request_content(bm, &content, &size);

			napi_value cnt;
			napi_create_string_utf8(env, (char *)content, size, &cnt);

			napi_status rc;
			napi_value result;
			rc = napi_make_callback(env, context, this_obj,
			                        func, 1, &cnt, &result);
			assert(rc == napi_ok);

			char res[4096] = {0};
			size_t in = 4096, out;
			napi_get_value_string_utf8(env, result, res, in, &out);
			bmsg_write_response_size(bm, res, out);
			bmsg_handled(bm);
		}

		napi_close_callback_scope(env, cb_scope);
		napi_async_destroy(env, context);
		napi_close_handle_scope(env, scope);
		item.second->reqs.clear();
	}

	pthread_mutex_unlock(&bd->service_lock);
}

static void servcall_async_cb(uv_async_t *handle)
{
	binding *bd = (binding *)uv_handle_get_data((uv_handle_t *)handle);

	pthread_mutex_lock(&bd->servcall_lock);

	for (auto &item : bd->servcall_list) {
		napi_handle_scope scope;
		napi_open_handle_scope(item->env, &scope);

		napi_value cnt;
		if (item->resp.empty()) {
			napi_create_string_utf8(item->env, "timeout",
			                        NAPI_AUTO_LENGTH, &cnt);
		} else {
			napi_create_string_utf8(item->env, item->resp.c_str(),
			                        NAPI_AUTO_LENGTH, &cnt);
		}

		napi_resolve_deferred(item->env, item->deferred, cnt);
		napi_close_handle_scope(item->env, scope);
		delete item;
	}
	bd->servcall_list.clear();

	pthread_mutex_unlock(&bd->servcall_lock);
}

static void subscribe_async_cb(uv_async_t *handle)
{
	binding *bd = (binding *)uv_handle_get_data((uv_handle_t *)handle);

	pthread_mutex_lock(&bd->subscribe_lock);

	for (auto &item : bd->subscribe_list) {
		napi_env env = item.second->env;
		napi_value this_obj = item.second->this_obj;
		napi_ref func_ref = item.second->func_ref;

		napi_handle_scope scope;
		napi_open_handle_scope(env, &scope);

		napi_async_context context;
		napi_value suba;
		napi_create_string_utf8(env, "suba", NAPI_AUTO_LENGTH, &suba);
		napi_async_init(env, nullptr, suba, &context);

		napi_callback_scope cb_scope;
		napi_open_callback_scope(env, nullptr, context, &cb_scope);

		napi_value func;
		napi_get_reference_value(env, func_ref, &func);

		for (auto &resp : item.second->resps) {
			napi_value cnt;
			napi_create_string_utf8(env, resp.c_str(),
			                        resp.size(), &cnt);
			napi_status rc;
			rc = napi_make_callback(env, context, this_obj,
			                        func, 1, &cnt, NULL);
			assert(rc == napi_ok);
		}

		napi_close_callback_scope(env, cb_scope);
		napi_async_destroy(env, context);
		napi_close_handle_scope(env, scope);
		item.second->resps.clear();
	}

	pthread_mutex_unlock(&bd->subscribe_lock);
}

static void bonfire_finalize(napi_env env, void *data, void *hint)
{
	binding *bd = (binding *)bonfire_get_user_data((struct bonfire *)data);
	task_destroy(bd->t);
	uv_close((uv_handle_t *)&bd->service_async, NULL);
	uv_close((uv_handle_t *)&bd->servcall_async, NULL);
	uv_close((uv_handle_t *)&bd->subscribe_async, NULL);
	pthread_mutex_destroy(&bd->service_lock);
	pthread_mutex_destroy(&bd->servcall_lock);
	pthread_mutex_destroy(&bd->subscribe_lock);

	uv_loop_t *loop;
	napi_get_uv_event_loop(env, &loop);
	uv_run(loop, UV_RUN_ONCE);
	delete bd;
	bonfire_destroy((struct bonfire *)data);
}

static napi_value bonfire_new_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 0;
	napi_value argv[0];
	napi_value this_obj = nullptr;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	binding *bd = new binding;
	uv_loop_t *loop;
	napi_get_uv_event_loop(env, &loop);
	uv_async_init(loop, &bd->service_async, service_async_cb);
	uv_async_init(loop, &bd->servcall_async, servcall_async_cb);
	uv_async_init(loop, &bd->subscribe_async, subscribe_async_cb);
	uv_handle_set_data((uv_handle_t *)&bd->service_async, bd);
	uv_handle_set_data((uv_handle_t *)&bd->servcall_async, bd);
	uv_handle_set_data((uv_handle_t *)&bd->subscribe_async, bd);
	pthread_mutex_init(&bd->service_lock, NULL);
	pthread_mutex_init(&bd->servcall_lock, NULL);
	pthread_mutex_init(&bd->subscribe_lock, NULL);

	struct bonfire *bf = bonfire_new();
	bonfire_set_user_data(bf, bd);
	napi_wrap(env, this_obj, bf, bonfire_finalize, NULL, NULL);
	bd->t = task_new_timeout(
		"btask", (task_timeout_func_t)bonfire_loop, bf, 1000);
	task_start(bd->t);
	return this_obj;
}

static void service_cb(struct bmsg *bm)
{
	void *header;
	size_t size;
	bmsg_get_request_header(bm, &header, &size);
	std::string hdr((char *)header, size);

	struct bonfire *bf = bmsg_get_bonfire(bm);
	binding *bd = (binding *)bonfire_get_user_data(bf);

	auto it = bd->service_list.find(hdr);
	if (it == bd->service_list.end())
		return;

	bmsg_pending(bm);
	pthread_mutex_lock(&bd->service_lock);
	it->second->reqs.push_back(bm);
	pthread_mutex_unlock(&bd->service_lock);
	uv_async_send(&bd->service_async);
}

static napi_value bonfire_connect_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 1;
	napi_value argv[1];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	char addr[256] = {0};
	size_t addr_in = 256, addr_out;
	napi_get_value_string_utf8(env, argv[0], addr, addr_in, &addr_out);

	struct bonfire *bf;
	napi_unwrap(env, this_obj, (void **)&bf);

	int rc = bonfire_connect(bf, addr);
	napi_value retval;
	napi_create_int32(env, rc, &retval);
	return retval;
}

static napi_value bonfire_disconnect_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 0;
	napi_value argv[0];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	struct bonfire *bf;
	napi_unwrap(env, this_obj, (void **)&bf);

	bonfire_disconnect(bf);
	return nullptr;
}

static napi_value bonfire_add_service_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 2;
	napi_value argv[2];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	char hdr[256] = {0};
	size_t hdr_in = 256, hdr_out;
	napi_get_value_string_utf8(env, argv[0], hdr, hdr_in, &hdr_out);

	struct bonfire *bf;
	napi_unwrap(env, this_obj, (void **)&bf);
	binding *bd = (binding *)bonfire_get_user_data(bf);

	bonfire_add_service(bf, hdr, service_cb);

	service_struct *ss = new struct service_struct;
	ss->header = hdr;
	ss->env = env;
	ss->this_obj = this_obj;
	napi_create_reference(env, argv[1], 1, &ss->func_ref);
	pthread_mutex_lock(&bd->service_lock);
	bd->service_list.insert(std::make_pair(hdr, ss));
	pthread_mutex_unlock(&bd->service_lock);
	return nullptr;
}

static napi_value bonfire_del_service_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 2;
	napi_value argv[2];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	char hdr[256] = {0};
	size_t hdr_in = 256, hdr_out;
	napi_get_value_string_utf8(env, argv[0], hdr, hdr_in, &hdr_out);

	struct bonfire *bf;
	napi_unwrap(env, this_obj, (void **)&bf);

	bonfire_del_service(bf, hdr);
	return nullptr;
}

static void servcall_cb(struct bonfire *bf, const void *resp,
                        size_t len, void *arg, int flag)
{
	struct servcall_struct *ss = (struct servcall_struct *)arg;
	binding *bd = (binding *)bonfire_get_user_data(bf);

	if (flag)
		ss->resp = "";
	else
		ss->resp = std::string((char *)resp, len);

	pthread_mutex_lock(&bd->servcall_lock);
	bd->servcall_list.push_back(ss);
	pthread_mutex_unlock(&bd->servcall_lock);
	uv_async_send(&bd->servcall_async);
}

static napi_value bonfire_servcall_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 2;
	napi_value argv[2];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	char hdr[256] = {0};
	size_t hdr_in = 256, hdr_out;
	napi_get_value_string_utf8(env, argv[0], hdr, hdr_in, &hdr_out);

	char cnt[4096] = {0};
	size_t cnt_in = 4096, cnt_out;
	napi_get_value_string_utf8(env, argv[1], cnt, cnt_in, &cnt_out);

	struct bonfire *bf;
	napi_unwrap(env, this_obj, (void **)&bf);

	struct servcall_struct *ss = new struct servcall_struct;
	ss->env = env;
	napi_value promise;
	napi_create_promise(env, &ss->deferred, &promise);
	bonfire_servcall_async(bf, hdr, cnt, servcall_cb, ss);
	return promise;
}

static napi_value bonfire_publish_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 2;
	napi_value argv[2];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	char topic[256] = {0};
	size_t topic_in = 256, topic_out;
	napi_get_value_string_utf8(env, argv[0], topic, topic_in, &topic_out);

	char cnt[4096] = {0};
	size_t cnt_in = 4096, cnt_out;
	napi_get_value_string_utf8(env, argv[1], cnt, cnt_in, &cnt_out);

	struct bonfire *bf;
	napi_unwrap(env, this_obj, (void **)&bf);

	int rc = bonfire_publish(bf, topic, cnt);
	napi_value retval;
	napi_create_int32(env, rc, &retval);
	return retval;
}

static void subscribe_cb(struct bonfire *bf, const void *resp,
                         size_t len, void *arg, int flag)
{
	subscribe_struct *ss = (subscribe_struct *)arg;
	binding *bd = (binding *)bonfire_get_user_data(bf);

	if (flag != BONFIRE_EOK) {
		uint32_t count;
		napi_reference_unref(ss->env, ss->func_ref, &count);
		fprintf(stderr, "%s: %d\n", __func__, count);
		pthread_mutex_lock(&bd->subscribe_lock);
		auto it = bd->subscribe_list.find(ss->topic);
		assert(it != bd->subscribe_list.end());
		bd->subscribe_list.erase(it);
		pthread_mutex_unlock(&bd->subscribe_lock);
		delete ss;
		return;
	}

	pthread_mutex_lock(&bd->subscribe_lock);
	ss->resps.push_back(std::string((char *)resp, len));
	pthread_mutex_unlock(&bd->subscribe_lock);
	uv_async_send(&bd->subscribe_async);
}

static napi_value bonfire_subscribe_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 2;
	napi_value argv[2];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	char topic[256] = {0};
	size_t topic_in = 256, topic_out;
	napi_get_value_string_utf8(env, argv[0], topic, topic_in, &topic_out);

	struct bonfire *bf;
	napi_unwrap(env, this_obj, (void **)&bf);
	binding *bd = (binding *)bonfire_get_user_data(bf);

	subscribe_struct *ss = new struct subscribe_struct;
	int rc = bonfire_subscribe(bf, topic, subscribe_cb, ss);
	if (rc) {
		delete ss;
	} else {
		ss->topic = topic;
		ss->env = env;
		ss->this_obj = this_obj;
		napi_create_reference(env, argv[1], 1, &ss->func_ref);
		pthread_mutex_lock(&bd->subscribe_lock);
		bd->subscribe_list.insert(std::make_pair(topic, ss));
		pthread_mutex_unlock(&bd->subscribe_lock);
	}

	napi_value retval;
	napi_create_int32(env, rc, &retval);
	return retval;
}

static napi_value bonfire_unsubscribe_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 1;
	napi_value argv[1];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	char topic[256] = {0};
	size_t topic_in = 256, topic_out;
	napi_get_value_string_utf8(env, argv[0], topic, topic_in, &topic_out);

	struct bonfire *bf;
	napi_unwrap(env, this_obj, (void **)&bf);

	int rc = bonfire_unsubscribe(bf, topic);
	napi_value retval;
	napi_create_int32(env, rc, &retval);
	return retval;
}

static napi_value Init(napi_env env, napi_value exports)
{
	napi_property_descriptor properties[8] = {
		DECLARE_NAPI_METHOD("connect", bonfire_connect_wrap),
		DECLARE_NAPI_METHOD("disconnect", bonfire_disconnect_wrap),
		DECLARE_NAPI_METHOD("addService", bonfire_add_service_wrap),
		DECLARE_NAPI_METHOD("delService", bonfire_del_service_wrap),
		DECLARE_NAPI_METHOD("servcall", bonfire_servcall_wrap),
		DECLARE_NAPI_METHOD("publish", bonfire_publish_wrap),
		DECLARE_NAPI_METHOD("subscribe", bonfire_subscribe_wrap),
		DECLARE_NAPI_METHOD("unsubscribe", bonfire_unsubscribe_wrap),
	};

	napi_value cons;
	napi_define_class(env, "bonfire", NAPI_AUTO_LENGTH, bonfire_new_wrap,
	                  NULL, _ARRAY_SIZE(properties), properties, &cons);
	napi_set_named_property(env, exports, "bonfire", cons);

	return exports;
}

NAPI_MODULE(bonfire, Init)
