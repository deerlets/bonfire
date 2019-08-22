#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <node_api.h>
#include <bonfire.h>

#define _ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define DECLARE_NAPI_METHOD(name, method) \
	{ name, NULL, method, NULL, NULL, NULL, napi_default, NULL }

struct async_struct {
	napi_value this_obj;
	napi_ref func_ref;
};

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

static void bonfire_finalize(napi_env env, void *data, void *hint)
{
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

	// bonfire_loop will call subscribe_cb
	bonfire_set_user_data(bf, env);
	bonfire_loop(bf, timeout);

	return nullptr;
}

static void servcall_cb(struct bonfire *bf, const void *resp,
                        size_t len, void *arg, int flag)
{
	struct async_struct *ss = (struct async_struct *)arg;
	napi_env env = (napi_env)bonfire_get_user_data(bf);

	napi_value func;
	napi_get_reference_value(env, ss->func_ref, &func);

	if (flag) {
		/*
		 * FIXME: We're in bonfire_loop, can't throw ...
		 * Try napi_async_init & napi_open_callback_scope
		 */
		//napi_throw_error(env, NULL, "11111");
		fprintf(stderr, "%s: %d\n", __func__, flag);
	} else {
		napi_value tmp;
		napi_create_string_utf8(env, (char *)resp, len, &tmp);
		napi_value cnt;
		parse(env, tmp, &cnt);
		napi_status rc;
		rc = napi_call_function(env, ss->this_obj, func, 1, &cnt, NULL);
		assert(rc == napi_ok);
	}

	uint32_t count;
	napi_reference_unref(env, ss->func_ref, &count);
	free(ss);
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

	struct async_struct *ss =
		(struct async_struct *)malloc(sizeof(*ss));
	ss->this_obj = this_obj;
	napi_create_reference(env, argv[2], 1, &ss->func_ref);

	bonfire_servcall_async(bf, hdr, cnt, servcall_cb, ss);
	return nullptr;
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
	struct async_struct *ss = (struct async_struct *)arg;
	napi_env env = (napi_env)bonfire_get_user_data(bf);

	if (resp == NULL) {
		uint32_t count;
		napi_reference_unref(env, ss->func_ref, &count);
		fprintf(stderr, "%s: %d\n", __func__, count);
		free(ss);
		return;
	}

	napi_value func;
	napi_get_reference_value(env, ss->func_ref, &func);

	napi_value tmp;
	napi_create_string_utf8(env, (char *)resp, len, &tmp);
	napi_value cnt;
	parse(env, tmp, &cnt);

	napi_status rc;
	rc = napi_call_function(env, ss->this_obj, func, 1, &cnt, NULL);
	assert(rc == napi_ok);
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

	struct async_struct *ss =
		(struct async_struct *)malloc(sizeof(*ss));
	ss->this_obj = this_obj;
	napi_create_reference(env, argv[1], 1, &ss->func_ref);

	int rc = bonfire_subscribe(bf, topic, subscribe_cb, ss);
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

	// bonfire_unsubscribe will call subscribe_cb
	bonfire_set_user_data(bf, env);
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
