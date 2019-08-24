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

static napi_status stringify(napi_env env, napi_value value, napi_value *result)
{
	napi_status rc;
	napi_value global, JSON, stringify;
	rc = napi_get_global(env, &global);
	assert(rc == napi_ok);
	rc = napi_get_named_property(env, global, "JSON", &JSON);
	assert(rc == napi_ok);
	rc = napi_get_named_property(env, JSON, "stringify", &stringify);
	assert(rc == napi_ok);
	rc = napi_call_function(env, global, stringify, 1, &value, result);
	return rc;
}

static napi_status parse(napi_env env, napi_value value, napi_value *result)
{
	napi_status rc;
	napi_value global, JSON, parse;
	rc = napi_get_global(env, &global);
	assert(rc == napi_ok);
	rc = napi_get_named_property(env, global, "JSON", &JSON);
	assert(rc == napi_ok);
	rc = napi_get_named_property(env, JSON, "parse", &parse);
	assert(rc == napi_ok);
	rc = napi_call_function(env, global, parse, 1, &value, result);
	return rc;
}

struct service_struct {
	std::string header;
	napi_env env;
	napi_value this_obj;
	napi_ref func_ref;
	napi_async_context context;
	std::list<struct bmsg *> reqs;
};

static uv_async_t service_async;
static std::map<std::string, service_struct *> service_list;
static pthread_mutex_t service_lock;

struct servcall_struct {
	napi_env env;
	napi_deferred deferred;
	std::string resp;
};

static uv_async_t servcall_async;
static std::list<servcall_struct *> servcall_list;
static pthread_mutex_t servcall_lock;

struct subscribe_struct {
	std::string topic;
	napi_env env;
	napi_value this_obj;
	napi_ref func_ref;
	napi_async_context context;
	std::list<std::string> resps;
};

static uv_async_t subscribe_async;
static std::map<std::string, subscribe_struct *> subscribe_list;
static pthread_mutex_t subscribe_lock;

static struct task *bonfire_task;

static void service_async_cb(uv_async_t *handle)
{
	pthread_mutex_lock(&service_lock);

	for (auto &item : service_list) {
		napi_env env = item.second->env;
		napi_value this_obj = item.second->this_obj;
		napi_ref func_ref = item.second->func_ref;
		napi_async_context context = item.second->context;

		napi_handle_scope scope;
		napi_open_handle_scope(env, &scope);

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
		napi_close_handle_scope(env, scope);
		item.second->reqs.clear();
	}

	pthread_mutex_unlock(&service_lock);
}

static void servcall_async_cb(uv_async_t *handle)
{
	pthread_mutex_lock(&servcall_lock);

	for (auto &item : servcall_list) {
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
	servcall_list.clear();

	pthread_mutex_unlock(&servcall_lock);
}

static void subscribe_async_cb(uv_async_t *handle)
{
	pthread_mutex_lock(&subscribe_lock);

	for (auto &item : subscribe_list) {
		napi_env env = item.second->env;
		napi_value this_obj = item.second->this_obj;
		napi_ref func_ref = item.second->func_ref;
		napi_async_context context = item.second->context;

		napi_handle_scope scope;
		napi_open_handle_scope(env, &scope);

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
		napi_close_handle_scope(env, scope);
		item.second->resps.clear();
	}

	pthread_mutex_unlock(&subscribe_lock);
}

static void bonfire_finalize(napi_env env, void *data, void *hint)
{
	task_destroy(bonfire_task);
	bonfire_destroy((struct bonfire *)data);

	pthread_mutex_destroy(&service_lock);
	pthread_mutex_destroy(&servcall_lock);
	pthread_mutex_destroy(&subscribe_lock);
}

static napi_value bonfire_new_wrap(napi_env env, napi_callback_info info)
{
	uv_loop_t *loop;
	napi_get_uv_event_loop(env, &loop);
	uv_async_init(loop, &service_async, service_async_cb);
	uv_async_init(loop, &servcall_async, servcall_async_cb);
	uv_async_init(loop, &subscribe_async, subscribe_async_cb);
	pthread_mutex_init(&service_lock, NULL);
	pthread_mutex_init(&servcall_lock, NULL);
	pthread_mutex_init(&subscribe_lock, NULL);

	size_t argc = 1;
	napi_value argv[1];
	napi_value this_obj = nullptr;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	char addr[64] = {0};
	size_t insize = 64, outsize;
	napi_get_value_string_utf8(env, argv[0], addr, insize, &outsize);

	struct bonfire *bf = bonfire_new(addr);
	napi_wrap(env, this_obj, bf, bonfire_finalize, NULL, NULL);
	return this_obj;
}

static napi_value bonfire_loop_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 1;
	napi_value argv[1];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	int64_t timeout;
	napi_get_value_int64(env, argv[0], &timeout);

	struct bonfire *bf;
	napi_unwrap(env, this_obj, (void **)&bf);

	bonfire_task = task_new_timeout(
		"btask", (task_timeout_func_t)bonfire_loop, bf, timeout);
	task_start(bonfire_task);

	return nullptr;
}

static void service_cb(struct bmsg *bm)
{
	void *header;
	size_t size;
	bmsg_get_request_header(bm, &header, &size);
	std::string hdr((char *)header, size);

	auto it = service_list.find(hdr);
	if (it == service_list.end())
		return;

	bmsg_pending(bm);
	pthread_mutex_lock(&service_lock);
	it->second->reqs.push_back(bm);
	pthread_mutex_unlock(&service_lock);
	uv_async_send(&service_async);
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

	bonfire_add_service(bf, hdr, service_cb);

	service_struct *ss = new struct service_struct;
	ss->header = hdr;
	ss->env = env;
	ss->this_obj = this_obj;
	napi_create_reference(env, argv[1], 1, &ss->func_ref);
	napi_async_init(env, nullptr, argv[0], &ss->context);
	pthread_mutex_lock(&service_lock);
	service_list.insert(std::make_pair(hdr, ss));
	pthread_mutex_unlock(&service_lock);
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

static napi_value bonfire_servsync_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 2;
	napi_value argv[2];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	struct bonfire *bf;
	napi_unwrap(env, this_obj, (void **)&bf);
	bonfire_servsync(bf);
	return nullptr;
}

static void servcall_cb(struct bonfire *bf, const void *resp,
                        size_t len, void *arg, int flag)
{
	struct servcall_struct *ss = (struct servcall_struct *)arg;

	if (flag)
		ss->resp = "";
	else
		ss->resp = std::string((char *)resp, len);

	pthread_mutex_lock(&servcall_lock);
	servcall_list.push_back(ss);
	pthread_mutex_unlock(&servcall_lock);
	uv_async_send(&servcall_async);
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

	if (flag != BONFIRE_OK) {
		uint32_t count;
		napi_reference_unref(ss->env, ss->func_ref, &count);
		fprintf(stderr, "%s: %d\n", __func__, count);
		napi_async_destroy(ss->env, ss->context);
		pthread_mutex_lock(&subscribe_lock);
		auto it = subscribe_list.find(ss->topic);
		assert(it != subscribe_list.end());
		subscribe_list.erase(it);
		pthread_mutex_unlock(&subscribe_lock);
		delete ss;
		return;
	}

	pthread_mutex_lock(&subscribe_lock);
	ss->resps.push_back(std::string((char *)resp, len));
	pthread_mutex_unlock(&subscribe_lock);
	uv_async_send(&subscribe_async);
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

	subscribe_struct *ss = new struct subscribe_struct;
	int rc = bonfire_subscribe(bf, topic, subscribe_cb, ss);
	if (rc) {
		delete ss;
	} else {
		ss->topic = topic;
		ss->env = env;
		ss->this_obj = this_obj;
		napi_create_reference(env, argv[1], 1, &ss->func_ref);
		napi_async_init(env, nullptr, argv[0], &ss->context);
		pthread_mutex_lock(&subscribe_lock);
		subscribe_list.insert(std::make_pair(topic, ss));
		pthread_mutex_unlock(&subscribe_lock);
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
		DECLARE_NAPI_METHOD("loop", bonfire_loop_wrap),
		DECLARE_NAPI_METHOD("addService", bonfire_add_service_wrap),
		DECLARE_NAPI_METHOD("delService", bonfire_del_service_wrap),
		DECLARE_NAPI_METHOD("servsync", bonfire_servsync_wrap),
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
