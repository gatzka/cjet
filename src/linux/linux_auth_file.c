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
#include <string.h>
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
#include "response.h"

static cJSON *user_data = NULL;
static const cJSON *users = NULL;
static int password_file = -1;

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

	int fd = open(rp, O_RDWR);
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
				if (add_groups(fetch_groups) < 0) {
					log_err("Fetch group is not an array in passwd file!\n");
					goto add_fetch_groups_failed;
				}
			}

			const cJSON *set_groups = cJSON_GetObjectItem(auth, "setGroups");
			if (set_groups != NULL) {
				if (add_groups(set_groups) < 0) {
					log_err("Set group is not an array in passwd file!\n");
					goto add_set_groups_failed;
				}
			}

			const cJSON *call_groups = cJSON_GetObjectItem(auth, "callGroups");
			if (call_groups != NULL) {
				if (add_groups(call_groups) < 0) {
					log_err("Call group is not an array in passwd file!\n");
					goto add_call_groups_failed;
				}
			}
		}

		user = user->next;
	}

	munmap(p, size);
	free(rp);

	password_file = fd;
	return 0;

add_call_groups_failed:
add_set_groups_failed:
add_fetch_groups_failed:
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

	close(password_file);
}

static void clear_password(char *passwd)
{
	for (char *p = passwd; *p != '\0'; p++) {
		*p = '\0';
	}
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
	clear_password(passwd);

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

static bool is_readonly(const char *user)
{
	(void)user;
	return false;
}

static bool is_admin(const char *user)
{
	(void)user;
	return false;
}

static int write_user_data()
{
	ftruncate(password_file, 0);
	lseek(password_file, 0, SEEK_SET);
	char *data = cJSON_Print(user_data);
	if (data != NULL) {
		cJSON_free(data);
	}

	ssize_t written = 0;
	ssize_t to_write = strlen(data);
	while (written < to_write) {
		written = write(password_file, data, to_write);
		if (written < 0) {
			log_err("Could not write password file\n");
			return -1;
		}
		to_write -= written;
	}

	return 0;
}

static void get_salt_from_passwd(char *salt, const char *passwd)
{
		// TODO: provide a good salt
	if (passwd[0] == '$') {
		const char *found = passwd;
		found++;
		found = strchr(found, '$');
		found++;
		found = strchr(found, '$');
		found++;
		strncpy(salt, passwd, found - passwd);
	} else {
		strncpy(salt, passwd, 2);
	}
}

cJSON *change_password(const struct peer *p, const cJSON *request, const char *user_name, char *passwd)
{
	cJSON *response = NULL;
	if (p->user_name == NULL) {
		response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "non-authenticated peer can't change any passwords");
		goto out;
	}

	if (!is_readonly(user_name) && ((strcmp(p->user_name, user_name) == 0) || (is_admin(user_name)))) {
		if (unlikely(user_data == NULL)) {
			response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no user database available");
			goto out;
		}

		cJSON *user = cJSON_GetObjectItem(users, user_name);
		if (user == NULL) {
			response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "user not in password database");
			goto out;
		}

		cJSON *password = cJSON_GetObjectItem(user, "password");
		if (password == NULL) {
			response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no password for user in password database");
			goto out;
		}

		if (password->type != cJSON_String) {
			response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "password for user in password database is not a string");
			goto out;
		}

		char salt[16];
		get_salt_from_passwd(salt, password->valuestring);

		struct crypt_data data;
		data.initialized = 0;
		char *encrypted = crypt_r(passwd, salt, &data);
		if (encrypted == NULL) {
			response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "could not encrypt password");
			goto out;
		}

		cJSON_ReplaceItemInObject(user, "password", cJSON_CreateString(encrypted));
		if (write_user_data() < 0) {
			response = create_error_response_from_request(p, request, INTERNAL_ERROR, "reason", "Could not write password file");
			goto out;
		}
	} else {
		response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "user not allowed to change password");
		goto out;
	}

	response = create_success_response_from_request(p, request);
out:
	clear_password(passwd);
	return response;
}
