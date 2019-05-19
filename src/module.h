#ifndef __ZSERV_MODULE_H
#define __ZSERV_MODULE_H

#include <limits.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VERSION_MAJOR(v) (v >> 24)
#define VERSION_MINOR(v) ((v >> 16) & 0xff)
#define VERSION_PATCH(v) ((v >> 8) & 0xff)
#define MAKE_VERSION(major, minor, patch) \
	((major << 24) + (minor << 16) + (patch << 8))

/*
 * errno
 */

enum MODULE_ERROR {
	MOD_ERELOAD,
	MOD_EOPEN,
	MOD_ESYM,
	MOD_EINIT,
	MOD_EEXIT,
};

int mod_errno(void);
char *mod_error(void);

/*
 * module init & exit
 */

struct module;

typedef int (*module_init_func_t)(struct module *m);
typedef void (*module_exit_func_t)(void);

static __attribute__((unused)) struct module *__module_self(struct module *m)
{ static struct module* __m; if (m) __m = m; return __m; }

#define module_init(init_func) \
	int __module_init(struct module *m) \
	{ __module_self(m); return init_func(); }

#define module_exit(exit_func) \
	void __module_exit(void) { exit_func(); }

#define THIS_MODULE __module_self(NULL)

/*
 * module & param
 */

struct module {
	char *filepath;
	char *filename;
	char *name;
	char *param;
	char *alias;
	char *desc;
	int version;
	void *handle;
	module_init_func_t init_fn;
	struct list_head node;
};

struct module *load_module(const char *filepath, const char *param);
int unload_module(struct module *m);

int load_modules_from_dir(const char *dirname);
int unload_all_modules(void);

struct module *find_module(const char *name);
struct list_head *get_modules();

void module_set_name(struct module *m, const char *name);
void module_set_info(struct module *m, const char *alias, const char *desc);
void module_set_version(struct module *m, int version);

int param_get_int(const char *name, int *value, const char *param);
int param_get_string(const char *name, void *buf,
                     size_t size, const char *param);

#define MODULE_PARAM_GET_INT(name, value) \
	param_get_int(name, value, THIS_MODULE->param)
#define MODULE_PARAM_GET_STRING(name, buf, size) \
	param_get_string(name, buf, size, THIS_MODULE->param)

#ifdef __cplusplus
}
#endif
#endif
