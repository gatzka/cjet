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
#include "json/cJSON.h"
#include "log.h"

static cJSON *user_data = NULL;
static const cJSON *users = NULL;

int load_passwd_data(const char *passwd_file)
{
	if (passwd_file == NULL) {
		return 0;
	}

	char *rp = realpath(passwd_file, NULL);
	if (rp == NULL) {
		return -1;
	}

	int fd = open(rp, O_RDONLY);
	if (fd == -1) {
		log_err("Cannot open passwd file: %s\n", passwd_file);
		return -1;
	}

	free(rp);

	off_t size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	int ret = 0;
	void *p = mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		log_err("Cannot mmap passwd file!\n");
		ret = -1;
		goto mmap_failed;
	}

	user_data = cJSON_ParseWithOpts(p, NULL, 0);
	if (user_data == NULL) {
		log_err("Cannot parse passwd file!\n");
		ret = -1;
		goto parse_failed;
	}

	users = cJSON_GetObjectItem(user_data, "users");
	if (users == NULL) {
		log_err("No user object in passwd file!\n");
		ret = -1;
		goto get_users_failed;
	}

get_users_failed:
parse_failed:
	munmap(p, size);
mmap_failed:
	close(fd);
	return ret;
}

void free_passwd_data(void)
{
	if (user_data != NULL) {
		cJSON_Delete(user_data);
		user_data = NULL;
		users = NULL;
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

	char *encrypted = crypt(passwd, password->valuestring);
	for (char *p = passwd; *p != '\0'; p++) {
		*p = '\0';
	}

	if (encrypted == NULL) {
		log_err("Error decrypting passwords\n");
	}

	if (strcmp(password->valuestring, encrypted) == 0) {
		const cJSON *auth = cJSON_GetObjectItem(user, "auth");
		if (auth == NULL) {
			log_err("No auth information for user %s in password file!\n", user_name);
			return NULL;
		}

		return auth;
	}

	return NULL;
}
