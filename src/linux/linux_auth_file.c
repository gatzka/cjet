/*
 *The MIT License (MIT)
 *
 * Copyright (c) <2016> <Stephan Gatzka>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <crypt.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc.h"
#include "authenticate.h"
#include "compiler.h"
#include "groups.h"
#include "json/cJSON.h"
#include "log.h"

static cJSON *user_data = NULL;
static const cJSON *users = NULL;

int load_passwd_data(const char *passwd_file)
{
	if (passwd_file == NULL) {
		return 0;
	}

	if (create_groups() < 0) {
		return -1;
	}

	char *rp = realpath(passwd_file, NULL);
	if (rp == NULL) {
		goto realpath_failed;
	}

	int fd = open(rp, O_RDONLY);
	if (fd == -1) {
		log_err("Cannot open passwd file: %s\n", passwd_file);
		goto open_failed;
	}

	off_t size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	void *p = mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		log_err("Cannot mmap passwd file!\n");
		goto mmap_failed;
	}

	user_data = cJSON_ParseWithOpts(p, NULL, 0);
	if (user_data == NULL) {
		log_err("Cannot parse passwd file!\n");
		goto parse_failed;
	}

	users = cJSON_GetObjectItem(user_data, "users");
	if (users == NULL) {
		log_err("No user object in passwd file!\n");
		goto get_users_failed;
	}

	const cJSON *user = users->child;
	while (user != NULL) {
		const cJSON *auth = cJSON_GetObjectItem(user, "auth");
		if (auth != NULL) {
			const cJSON *fetch_groups = cJSON_GetObjectItem(auth, "fetchGroups");
			if (fetch_groups != NULL) {
				add_groups(fetch_groups);
			}
			const cJSON *set_groups = cJSON_GetObjectItem(auth, "setGroups");
			if (set_groups != NULL) {
				add_groups(set_groups);
			}
			const cJSON *call_groups = cJSON_GetObjectItem(auth, "callGroups");
			if (call_groups != NULL) {
				add_groups(call_groups);
			}
		}
		user = user->next;
	}

	munmap(p, size);
	close(fd);
	free(rp);

	return 0;

get_users_failed:
parse_failed:
	munmap(p, size);
mmap_failed:
	close(fd);
open_failed:
	free(rp);
realpath_failed:
	free_groups();
	return -1;
}

void free_passwd_data(void)
{
	if (user_data != NULL) {
		cJSON_Delete(user_data);
		user_data = NULL;
		users = NULL;
	}

	free_groups();
}

const cJSON *credentials_ok(const char *user_name, char *passwd)
{
	if (unlikely(user_data == NULL)) {
		return NULL;
	}

	cJSON *user = cJSON_GetObjectItem(users, user_name);
	if (user == NULL) {
		return NULL;
	}

	cJSON *password = cJSON_GetObjectItem(user, "password");
	if (password == NULL) {
		log_err("No password for user %s in password file!\n", user_name);
		return NULL;
	}

	if (password->type != cJSON_String) {
		log_err("password for user %s in password file is not a string!\n", user_name);
		return NULL;
	}

	struct crypt_data data;
	data.initialized = 0;

	char *encrypted = crypt_r(passwd, password->valuestring, &data);
	for (char *p = passwd; *p != '\0'; p++) {
		*p = '\0';
	}

	if (encrypted == NULL) {
		log_err("Error decrypting passwords\n");
		return NULL;
	}

	const cJSON *auth = NULL;
	if (strcmp(password->valuestring, encrypted) == 0) {
		auth = cJSON_GetObjectItem(user, "auth");
		if (auth == NULL) {
			log_err("No auth information for user %s in password file!\n", user_name);
		}
	}

	return auth;
}
