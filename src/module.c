#include "module.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>

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

static void path_to_name(const char *filepath, char *name, size_t size)
{
	char *__filepath = strdup(filepath);

	// FIXME: windows may use '\\'
	char *start = strrchr(__filepath, '/');
	if (!start) start = __filepath;
	else start++;

	char *end = __filepath + strlen(__filepath);

	size_t len = end - start;
	if (len > size) len = size;

	memset(name, 0, size);
	memcpy(name, start, len);

	free(__filepath);
}

struct module *load_module(const char *filepath, const char *param)
{
	char fullname[MODULE_NAME_SIZE];
	path_to_name(filepath, fullname, sizeof(fullname));

	if (find_module(fullname)) {
		__errno = MOD_ERELOAD;
		return NULL;
	}

	void *handle = dlopen(filepath, RTLD_LAZY | RTLD_GLOBAL);
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
	memset(m, 0, sizeof(*m));
	snprintf(m->filepath, sizeof(m->filepath), "%s", filepath);
	snprintf(m->fullname, sizeof(m->fullname), "%s", fullname);
	snprintf(m->name, sizeof(m->name), "%s", fullname);
	snprintf(m->param, sizeof(m->param), "%s", param);
	m->version = 0;
	m->handle = handle;
	m->init_fn = func;
	INIT_LIST_HEAD(&m->node);
	list_add(&m->node, &modules);

	if ((*func)(m)) {
		dlclose(handle);
		__errno = MOD_EINIT;
		snprintf(__errmsg, MODULE_ERRMSG_SIZE,
		         "module_init of %s failed!\n", filepath);
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
	} else {
		(*func)();
	}

	assert(dlclose(m->handle) == 0);
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
#ifdef __unix
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
		if (!strcmp(pos->name, name) || !strcmp(pos->fullname, name))
			return pos;
	}

	return NULL;
}

struct list_head *get_modules()
{
	return &modules;
}

void module_set_name(struct module *m, const char *name)
{
	snprintf(m->name, sizeof(m->name), "%s", name);
}

void module_set_version(struct module *m, int version)
{
	m->version = version;
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
