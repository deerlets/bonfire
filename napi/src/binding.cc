#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
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

struct servcall_struct {
	napi_env env;
	napi_deferred deferred;
	std::string resp;
};

static uv_async_t servcall_async;
static std::list<servcall_struct *> servcall_list;

struct subscribe_struct {
	std::string topic;
	napi_env env;
	napi_value this_obj;
	napi_ref func_ref;
	std::list<std::string> resps;
};

static uv_async_t subscribe_async;
static std::map<std::string, subscribe_struct *> subscribe_list;

static struct task *bonfire_task;

static void servcall_async_cb(uv_async_t *handle)
{
	for (auto &item : servcall_list) {
		napi_handle_scope scope;
		napi_open_handle_scope(item->env, &scope);

		if (item->resp.empty()) {
			napi_value cnt;
			napi_create_string_utf8(item->env, "timeout",
			                        NAPI_AUTO_LENGTH, &cnt);
			napi_reject_deferred(item->env, item->deferred, cnt);
		} else {
			napi_value tmp;
			napi_create_string_utf8(item->env, item->resp.c_str(),
			                        NAPI_AUTO_LENGTH, &tmp);
			napi_value cnt;
			parse(item->env, tmp, &cnt);
			napi_resolve_deferred(item->env, item->deferred, cnt);
		}

		napi_close_handle_scope(item->env, scope);
		delete item;
	}

	servcall_list.clear();
}

static void subscribe_async_cb(uv_async_t *handle)
{
	for (auto &item : subscribe_list) {
		napi_env env = item.second->env;
		napi_value this_obj = item.second->this_obj;
		napi_ref func_ref = item.second->func_ref;

		napi_handle_scope scope;
		napi_open_handle_scope(env, &scope);

		napi_value func;
		napi_get_reference_value(env, func_ref, &func);

		for (auto &resp : item.second->resps) {
			napi_value tmp;
			napi_create_string_utf8(env, resp.c_str(),
			                        resp.size(), &tmp);
			napi_value cnt;
			parse(env, tmp, &cnt);

			napi_status rc;
			rc = napi_call_function(env, this_obj, func,
			                        1, &cnt, NULL);
			assert(rc == napi_ok);
		}

		napi_close_handle_scope(env, scope);
		item.second->resps.clear();
	}
}

static void bonfire_finalize(napi_env env, void *data, void *hint)
{
	task_destroy(bonfire_task);
	bonfire_destroy((struct bonfire *)data);
}

static napi_value bonfire_new_wrap(napi_env env, napi_callback_info info)
{
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

	uv_loop_t *loop;
	napi_get_uv_event_loop(env, &loop);
	uv_async_init(loop, &servcall_async, servcall_async_cb);
	uv_async_init(loop, &subscribe_async, subscribe_async_cb);
	bonfire_task = task_new_timeout(
		"btask", (task_timeout_func_t)bonfire_loop, bf, timeout);
	task_start(bonfire_task);

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

	servcall_list.push_back(ss);
	uv_async_send(&servcall_async);
}

static napi_value bonfire_servcall_wrap(napi_env env, napi_callback_info info)
{
	size_t argc = 3;
	napi_value argv[3];
	napi_value this_obj;
	napi_get_cb_info(env, info, &argc, argv, &this_obj, nullptr);

	char hdr[256] = {0};
	size_t hdr_in = 256, hdr_out;
	napi_get_value_string_utf8(env, argv[0], hdr, hdr_in, &hdr_out);

	napi_value tmp;
	stringify(env, argv[1], &tmp);
	char cnt[4096] = {0};
	size_t cnt_in = 4096, cnt_out;
	napi_get_value_string_utf8(env, tmp, cnt, cnt_in, &cnt_out);

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

static void
subscribe_cb(struct bonfire *bf, const void *resp, size_t len, void *arg)
{
	subscribe_struct *ss = (subscribe_struct *)arg;

	if (resp == NULL) {
		uint32_t count;
		napi_reference_unref(ss->env, ss->func_ref, &count);
		fprintf(stderr, "%s: %d\n", __func__, count);
		auto it = subscribe_list.find(ss->topic);
		assert(it != subscribe_list.end());
		subscribe_list.erase(it);
		delete ss;
		return;
	}

	ss->resps.push_back(std::string((char *)resp, len));
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
		subscribe_list.insert(std::make_pair(topic, ss));
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
	napi_property_descriptor properties[5] = {
		DECLARE_NAPI_METHOD("loop", bonfire_loop_wrap),
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
