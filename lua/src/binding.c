#include <stdlib.h>
#include <string.h>
#include <lua5.3/lua.h>
#include <lua5.3/lualib.h>
#include <lua5.3/lauxlib.h>
#include <bonfire.h>

static lua_State *__L;

/*static*/ void stack_dump(lua_State *L) {
    int i = lua_gettop(L);
    printf("============> Stack Dump\n");
    while(i) {
        int t = lua_type(L, i);
        switch (t) {
        case LUA_TSTRING:
            printf("%d: %s\n", i, lua_tostring(L, i));
            break;
        case LUA_TBOOLEAN:
            printf("%d: %s\n", i,
                   lua_toboolean(L, i) ? "true" : "false");
            break;
        case LUA_TNUMBER:
            printf("%d: %g\n", i, lua_tonumber(L, i));
            break;
        default: printf("%d: %s\n", i, lua_typename(L, t));
            break;
        }
        i--;
    }
    printf("============> Stack Dump Finished\n");
}

static void service_cb(struct bmsg *bm)
{
    void *header;
    size_t header_size;
    bmsg_get_request_header(bm, &header, &header_size);

    void *content;
    size_t content_size;
    bmsg_get_request_content(bm, &content, &content_size);

    lua_pushlstring(__L, header, header_size);
    lua_gettable(__L, 1);
    int cb_ref = luaL_checkinteger(__L, -1);

    lua_rawgeti(__L, LUA_REGISTRYINDEX, cb_ref);
    lua_pushlstring(__L, content, content_size);
    lua_pcall(__L, 1, 1, 0);
    const char *result = luaL_checkstring(__L, -1);

    bmsg_write_response_size(bm, result, strlen(result));
}

static void subscribe_cb(struct bonfire *bf, const void *resp,
                         size_t len, void *arg, int flag)
{
    if (flag != BONFIRE_EOK) {
        free(arg);
        return;
    }

    const char *header = arg;
    lua_getfield(__L, 1, header);
    int cb_ref = luaL_checkinteger(__L, -1);

    lua_rawgeti(__L, LUA_REGISTRYINDEX, cb_ref);
    lua_pushlstring(__L, resp, len);
    lua_pcall(__L, 1, 0, 0);
}

static int bonfire_new_wrap(lua_State *L)
{
    struct bonfire *bf = bonfire_new();
    lua_newtable(L);
    lua_pushlightuserdata(L, bf);
    lua_setfield(L, -2, "bf");
    return 1;
}

static int bonfire_destroy_wrap(lua_State *L)
{
    stack_dump(L);
    lua_getfield(L, 1, "bf");
    struct bonfire *bf = lua_touserdata(L, -1);
    bonfire_destroy(bf);
    return 0;
}

static int bonfire_loop_wrap(lua_State *L)
{
    lua_getfield(L, 1, "bf");
    struct bonfire *bf = lua_touserdata(L, -1);
    long timeout = luaL_checkinteger(L, 2);
    int rc = bonfire_loop(bf, timeout);
    lua_pushinteger(L, rc);
    return 1;
}

static int bonfire_connect_wrap(lua_State *L)
{
    lua_getfield(L, 1, "bf");
    struct bonfire *bf = lua_touserdata(L, -1);
    const char *addr = luaL_checkstring(L, 2);
    int rc = bonfire_connect(bf, addr);
    lua_pushinteger(L, rc);
    return 1;
}

static int bonfire_disconnect_wrap(lua_State *L)
{
    lua_getfield(L, 1, "bf");
    struct bonfire *bf = lua_touserdata(L, -1);
    bonfire_disconnect(bf);
    return 1;
}

static int bonfire_add_service_wrap(lua_State *L)
{
    lua_getfield(L, 1, "bf");
    struct bonfire *bf = lua_touserdata(L, -1);
    const char *header = luaL_checkstring(L, 2);
    lua_pushvalue(L, 3);
    int cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushinteger(L, cb_ref);
    lua_setfield(L, 1, header);
    int rc = bonfire_add_service(bf, header, service_cb);
    lua_pushinteger(L, rc);
    return 1;
}

static int bonfire_del_service_wrap(lua_State *L)
{
    lua_getfield(L, 1, "bf");
    struct bonfire *bf = lua_touserdata(L, -1);
    const char *header = luaL_checkstring(L, 2);
    bonfire_del_service(bf, header);
    return 0;
}

static int bonfire_servcall_wrap(lua_State *L)
{
    lua_getfield(L, 1, "bf");
    struct bonfire *bf = lua_touserdata(L, -1);
    const char *header = luaL_checkstring(L, 2);
    const char *content = luaL_checkstring(L, 3);
    char *result = NULL;
    int rc = bonfire_servcall(bf, header, content, &result);
    lua_pushinteger(L, rc);
    lua_pushstring(L, result);
    free(result);
    return 2;
}

static int bonfire_publish_wrap(lua_State *L)
{
    lua_getfield(L, 1, "bf");
    struct bonfire *bf = lua_touserdata(L, -1);
    const char *header = luaL_checkstring(L, 2);
    const char *content = luaL_checkstring(L, 3);
    int rc = bonfire_publish(bf, header, content);
    lua_pushinteger(L, rc);
    return 1;
}

static int bonfire_subscribe_wrap(lua_State *L)
{
    lua_getfield(L, 1, "bf");
    struct bonfire *bf = lua_touserdata(L, -1);
    const char *header = luaL_checkstring(L, 2);
    void *arg = strdup(header);
    int rc = bonfire_subscribe(bf, header, subscribe_cb, arg);

    if (rc) {
        free(arg);
    } else {
        lua_pushvalue(L, 3);
        int cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        lua_pushinteger(L, cb_ref);
        lua_setfield(L, 1, header);
    }

    lua_pushinteger(L, rc);
    return 1;
}

static int bonfire_unsubscribe_wrap(lua_State *L)
{
    lua_getfield(L, 1, "bf");
    struct bonfire *bf = lua_touserdata(L, -1);
    const char *header = luaL_checkstring(L, 2);
    int rc = bonfire_unsubscribe(bf, header);

    if (!rc) {
        lua_pushvalue(L, 3);
        lua_pushnil(L);
        lua_setfield(L, 1, header);
    }

    lua_pushinteger(L, rc);
    return 1;
}

static const struct luaL_Reg funcs[] = {
    {"new", bonfire_new_wrap},
    {"destroy", bonfire_destroy_wrap},
    {"loop", bonfire_loop_wrap},
    {"connect", bonfire_connect_wrap},
    {"disconnect", bonfire_disconnect_wrap},
    {"add_service", bonfire_add_service_wrap},
    {"del_service", bonfire_del_service_wrap},
    {"servcall", bonfire_servcall_wrap},
    {"publish", bonfire_publish_wrap},
    {"subscribe", bonfire_subscribe_wrap},
    {"unsubscribe", bonfire_unsubscribe_wrap},
    {NULL, NULL},
};

extern int luaopen_bonfirelua(lua_State *L)
{
    __L = L;
    luaL_newlib(L, funcs);
    return 1;
}
