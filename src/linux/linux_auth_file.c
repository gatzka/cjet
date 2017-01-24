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

#ifndef ARRAY_SIZE
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static cJSON *user_data = NULL;
static const cJSON *users = NULL;
static int password_file = -1;

struct crypt_method {
	const char *prefix; /* salt prefix */
	const unsigned int minlen; /* minimum salt length */
	const unsigned int maxlen; /* maximum salt length */
	const unsigned int rounds; /* supports a variable number of rounds */
};

static const struct crypt_method methods[] = {
	{"", 2, 2, 0}, /* DES */
	{"$1$", 8, 8, 0}, /* MD5 */
	{"$5$", 8, 16, 1}, /* SHA-256 */
	{"$6$", 8, 16, 1} /* SHA-512 */
};

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
	cJSON_Delete(user_data);
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

	if (password_file != -1) {
		close(password_file);
	}
}

static void clear_password(char *passwd)
{
	for (char *p = passwd; *p != '\0'; p++) {
		*p = '\0';
	}
}

const cJSON *credentials_ok(const char *user_name, char *passwd)
{
	const cJSON *auth = NULL;

	if (unlikely(user_data == NULL)) {
		goto out;
	}

	cJSON *user = cJSON_GetObjectItem(users, user_name);
	if (user == NULL) {
		goto out;
	}

	cJSON *password = cJSON_GetObjectItem(user, "password");
	if (password == NULL) {
		log_err("No password for user %s in password file!\n", user_name);
		goto out;
	}

	if (password->type != cJSON_String) {
		log_err("password for user %s in password file is not a string!\n", user_name);
		goto out;
	}

	struct crypt_data data;
	data.initialized = 0;

	char *encrypted = crypt_r(passwd, password->valuestring, &data);

	if (encrypted == NULL) {
		log_err("Error decrypting passwords\n");
		goto out;
	}

	if (strcmp(password->valuestring, encrypted) == 0) {
		auth = cJSON_GetObjectItem(user, "auth");
		if (auth == NULL) {
			log_err("No auth information for user %s in password file!\n", user_name);
		}
	}

out:
	clear_password(passwd);
	return auth;
}

static bool is_readonly(const cJSON *user)
{
	cJSON *readonly = cJSON_GetObjectItem(user, "readonly");
	if (readonly == NULL) {
		return false;
	}

	if (readonly->type == cJSON_True) {
		return true;
	}

	return false;
}

static bool is_admin(const char *current_user)
{
	cJSON *user = cJSON_GetObjectItem(users, current_user);
	if (user == NULL) {
		return false;
	}

	cJSON *admin = cJSON_GetObjectItem(user, "admin");
	if (admin == NULL) {
		return false;
	}

	if (admin->type == cJSON_True) {
		return true;
	}

	return false;
}

static int write_user_data()
{
	if (ftruncate(password_file, 0) < 0){
		log_err("Could not truncate password file\n");
		return -1;
	}

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

static void fill_salt(char *buf, unsigned int salt_len)
{
	static const char valid_salts[] = "abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

	unsigned int i;
	for (i = 0; i < salt_len; i++)
		buf[i] = valid_salts[rand() % (sizeof valid_salts - 1)];
	buf[i++] = '$';
	buf[i] = '\0';
}

static int get_salt_from_passwd(char *salt, const char *passwd)
{
	const char *method = NULL;
	int method_index = -1;
	if (passwd[0] == '$') {
		const char *found = passwd;
		found++;
		found = strchr(found, '$');
		found++;
		unsigned int num_methods = ARRAY_SIZE(methods);
		for (unsigned int i = 0; i < num_methods; i++) {
			const struct crypt_method *crypt_method = &methods[i];
			if (strncmp(passwd, crypt_method->prefix, found - passwd) == 0) {
				method_index = i;
				break;
			}
		}
	} else {
		method_index = 0;
	}

	if (method_index < 0) {
		log_err("password salt method not supported\n");
		return -1;
	}

	method = methods[method_index].prefix;
	unsigned int salt_minlen = methods[method_index].minlen;
	unsigned int salt_maxlen = methods[method_index].maxlen;

	unsigned int salt_len = salt_maxlen;
	if (salt_minlen != salt_maxlen) {
		salt_len = rand() % (salt_maxlen - salt_minlen + 1) + salt_minlen;
	}

	salt[0] = '\0';
	strcat(salt, method);
	fill_salt(salt + strlen(salt), salt_len);

	return 0;
}

cJSON *change_password(const struct peer *p, const cJSON *request, const char *user_name, char *passwd)
{
	cJSON *response = NULL;
	if (p->user_name == NULL) {
		response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "non-authenticated peer can't change any passwords");
		goto out;
	}

	cJSON *user = cJSON_GetObjectItem(users, user_name);
	if (user == NULL) {
		response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "user not in password database");
		goto out;
	}

	if (!is_readonly(user) && ((strcmp(p->user_name, user_name) == 0) || (is_admin(p->user_name)))) {
		if (unlikely(user_data == NULL)) {
			response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "no user database available");
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

		char salt[22];
		if (get_salt_from_passwd(salt, password->valuestring) < 0) {
			response = create_error_response_from_request(p, request, INVALID_PARAMS, "reason", "can't create salt for new password");
			goto out;
		}

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
