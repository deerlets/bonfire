#include "module.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>

#define MODULE_ERRMSG_SIZE 512

static int __errno;
static char __errmsg[MODULE_ERRMSG_SIZE];
static LIST_HEAD(modules);

int mod_errno(void)
{
	return __errno;
}

char *mod_error(void)
{
	return __errmsg;
}

static void path_to_name(char *fpath, char *name, size_t size)
{
	// FIXME: windows may use '\\'
	char *start = strrchr(fpath, '/');
	if (!start) start = fpath;
	else start++;

	char *end = strrchr(fpath, '.');
	if (!end) end = fpath + strlen(fpath);

	size_t len = end - start;
	if (len > size) len = size;

	memset(name, 0, size);
	memcpy(name, start, len);
}

struct module *module_self(void *address)
{
	struct module *pos;
	list_for_each_entry(pos, &modules, node) {
		if (address == pos->init_fn)
			return pos;
	}

	return NULL;
}

struct module *load_module(const char *fpath, const char *param)
{
	char __name[MODULE_NAME_SIZE];
	char __fpath[PATH_MAX];
	strcpy(__fpath, fpath);
	path_to_name(__fpath, __name, sizeof(__name));

	if (find_module(__name)) {
		__errno = MOD_ERELOAD;
		return NULL;
	}

	void *handle = dlopen(fpath, RTLD_LAZY);
	if (handle == NULL) {
		__errno = MOD_EOPEN;
		snprintf(__errmsg, MODULE_ERRMSG_SIZE, "%s", dlerror());
		return NULL;
	}

	module_init_func_t func = dlsym(handle, "__module_init");
	if (!func) {
		dlclose(handle);
		__errno = MOD_ESYM;
		snprintf(__errmsg, MODULE_ERRMSG_SIZE, "%s", dlerror());
		return NULL;
	}

	struct module *m = malloc(sizeof(struct module));
	snprintf(m->fpath, sizeof(m->fpath), "%s", fpath);
	snprintf(m->name, sizeof(m->name), "%s", __name);
	snprintf(m->param, sizeof(m->param), "%s", param);
	m->handle = handle;
	m->init_fn = func;
	INIT_LIST_HEAD(&m->node);
	list_add(&m->node, &modules);

	if ((*func)()) {
		dlclose(handle);
		__errno = MOD_EINIT;
		snprintf(__errmsg, MODULE_ERRMSG_SIZE,
		         "module_init of %s failed!\n", fpath);
		list_del(&m->node);
		free(m);
		return NULL;
	}

	return m;
}

int unload_module(struct module *m)
{
	module_exit_func_t func = dlsym(m->handle, "__module_exit");
	if (!func) {
		__errno = MOD_ESYM;
		snprintf(__errmsg, MODULE_ERRMSG_SIZE, "%s", dlerror());
		return -1;
	}
	(*func)();

	dlclose(m->handle);
	list_del(&m->node);
	free(m);
	return 0;
}

int load_modules_from_dir(const char *dirname)
{
	int rc = 0;

	DIR *dir = opendir(dirname);
	if (dir == NULL) {
		__errno = MOD_EOPEN;
		snprintf(__errmsg, MODULE_ERRMSG_SIZE, "%s", strerror(errno));
		return -1;
	}

	struct dirent *entry;
	char buf[512];
	while ((entry = readdir(dir))) {
#ifdef unix
		if (strncmp(entry->d_name, ".", 2) == 0 ||
		    strncmp(entry->d_name, "..", 3) == 0 ||
		    (entry->d_type != DT_REG && entry->d_type != DT_LNK))
			continue;
#else
		if (strncmp(entry->d_name, ".", 2) == 0 ||
		    strncmp(entry->d_name, "..", 3) == 0)
			continue;
#endif

		snprintf(buf, sizeof(buf), "%s/%s", dirname, entry->d_name);
		if (load_module(buf, NULL) == NULL)
			rc = -1;
	}

	closedir(dir);
	return rc;
}

int unload_all_modules(void)
{
	int rc = 0;

	struct module *pos, *n;
	list_for_each_entry_safe(pos, n, &modules, node) {
		if (unload_module(pos) != 0)
			rc = -1;
	}

	return rc;
}

struct module *find_module(const char *name)
{
	struct module *pos;
	list_for_each_entry(pos, &modules, node) {
		if (strstr(pos->name, name) != NULL)
			return pos;
	}

	return NULL;
}

struct list_head *get_modules()
{
	return &modules;
}

int param_get_int(const char *name, int *value, const char *param)
{
	char *start, *end;

	start = strstr(param, name);
	if (!start) return -1;

	start = strchr(start, '=');
	if (!start) return -1;
	start++;

	end = strchr(start, ' ');
	if (!end) end = strchr(start, '\0');

	void *tmp = malloc(end - start + 1);
	memset(tmp, 0, end - start + 1);
	memcpy(tmp, start, end - start);

	*value = atoi(tmp);
	free(tmp);
	return 0;
}

int param_get_string(const char *name, void *buf, size_t size, const char *param)
{
	char *start, *end;

	start = strstr(param, name);
	if (!start) return -1;

	start = strchr(start, '=');
	if (!start) return -1;
	start++;

	if (*start == '"') {
		start++;
		end = strchr(start, '"');
		if (!end) return -1;
	} else {
		end = strchr(start, ' ');
		if (!end) end = strchr(start, '\0');
	}

	memset(buf, 0, size);
	memcpy(buf, start, size - 1 < end - start ? size - 1 : end - start);
	return 0;
}
