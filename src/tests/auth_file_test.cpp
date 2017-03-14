/*
 * The MIT License (MIT)
 *
 * Copyright (c) <2017> <Thomas Ballenthin>
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

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE linux auth test
#define BOOST_FILESYSTEM_NO_DEPRECATED

#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>
#include <fstream>
#include <iostream>

#include "authenticate.h"
#include "peer.h"
#include "json/cJSON.h"

extern "C" {
int cjet_timer_init(struct cjet_timer *timer, struct eventloop *loop)
{
	(void)timer;
	(void)loop;
	return 0;
}

void cjet_timer_destroy(struct cjet_timer *timer)
{
	(void)timer;
}

void cjet_get_random_bytes(void *bytes, size_t num_bytes)
{
	uint8_t *buffer = (uint8_t *)bytes;
	srand(time(NULL));
	int random_number;

	for (size_t i = 0; i < num_bytes; i++) {
		random_number = rand();
		*buffer = random_number & 0xff;
		buffer++;
	}
}
}

static std::string create_temp_copy_of_file(std::string source_filename, std::string filename_apendix)
{
	std::string destination_filename(source_filename);
	destination_filename.append(filename_apendix);

	std::ifstream source(source_filename.c_str(), std::ios::binary);
	std::ofstream dest(destination_filename.c_str(), std::ios::binary);

	BOOST_REQUIRE_MESSAGE(source.is_open(), "Can't open source file: " << source_filename);
	BOOST_REQUIRE_MESSAGE(dest.is_open(), "Can't open destination file: " << destination_filename);
	dest << source.rdbuf();

	source.close();
	dest.close();

	return destination_filename;
}

static bool response_is_error(const cJSON *response)
{
	const cJSON *error = cJSON_GetObjectItem(response, "error");
	return (error != NULL);
}

char *extract_error_message(const cJSON *request_error)
{

	const cJSON *error = cJSON_GetObjectItem(request_error, "error");
	BOOST_REQUIRE_MESSAGE(error != NULL, "No error object given!");

	const cJSON *error_data = cJSON_GetObjectItem(error, "data");
	BOOST_REQUIRE_MESSAGE(error_data != NULL, "No data object within given error message!");

	const cJSON *error_string_reason = cJSON_GetObjectItem(error_data, "reason");
	if (error_string_reason != NULL) {
		BOOST_REQUIRE_MESSAGE(error_string_reason->type == cJSON_String, "Given reason is no string!");
		return error_string_reason->valuestring;
	} else {
		const cJSON *error_string_auth = cJSON_GetObjectItem(error_data, "fetched before authenticate");
		if (error_string_auth == NULL) {
			BOOST_FAIL("no object reason given within error message");
			return NULL;
		} else {
			return error_string_auth->string;
		}
	}
}

struct peer *alloc_peer()
{
	struct peer *p = (struct peer *)::malloc(sizeof(*p));
	p->name = NULL;
	p->user_name = NULL;
	p->is_local_connection = false;
	p->loop = NULL;
	p->send_message = NULL;
	return p;
}

void free_peer(struct peer *p) { ::free(p); }

struct F {
	F()
	{
		std::string argv(boost::unit_test::framework::master_test_suite().argv[0]);
		boost::filesystem::path exec_path = boost::filesystem::system_complete(argv).parent_path();
		std::string temporarily_file = create_temp_copy_of_file(exec_path.string() + "/input_data/passwd_std.json", "_temp");
		int response = load_passwd_data((exec_path.string() + "/input_data/passwd_std.json_temp").c_str());
		BOOST_REQUIRE_MESSAGE(response == 0, "Loading password file failed.");
	}

	~F()
	{
		free_passwd_data();
	}
};

BOOST_AUTO_TEST_CASE(check_load_passwd_data_error_paths)
{
	int response = load_passwd_data(NULL);
	BOOST_CHECK_MESSAGE(response == 0, "Expected 0 as return value when calling load_passwd_data(NULL).");

	response = load_passwd_data("*/___/");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when calling realpath with '*/___/'.");

	response = load_passwd_data("some_non_existing_file_641587976.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening non-existing file.");

	response = load_passwd_data("input_data/no_json.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening non JSON file.");

	response = load_passwd_data("input_data/passwd_no_user_data.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening passwd file without user data.");

	response = load_passwd_data("input_data/passwd_fetch_group_no_array.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening passwd file without array as fetch group.");

	response = load_passwd_data("input_data/passwd_set_group_no_array.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening passwd file without array as set group.");

	response = load_passwd_data("input_data/passwd_call_group_no_array.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening passwd file without array as callgroup.");

	response = load_passwd_data("input_data/passwd_no_json_data.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening passwd file without any JSON.");
}

BOOST_FIXTURE_TEST_CASE(check_credentials, F)
{
	char username[] = "john";
	char passwd[] = "doe";

	char unknown_user[] = "mister_x";
	char passwd_to_null[] = "doe";

	char user_no_passwd[] = "john-no_passwd";
	char user_passwd_no_string[] = "john-pw_no_string";

	const cJSON *response1 = credentials_ok(NULL, NULL);
	BOOST_CHECK_MESSAGE(response1 == NULL, "Response should be NULL when no user_name nor passwd is provided.");

	const cJSON *response2 = credentials_ok(username, NULL);
	BOOST_CHECK_MESSAGE(response2 == NULL, "Response should be NULL when no passwd is provided.");

	const cJSON *response3 = credentials_ok(NULL, passwd_to_null);
	BOOST_CHECK_MESSAGE(response3 == NULL, "Response should be NULL when no user_name is provided.");
	BOOST_CHECK_MESSAGE(std::strcmp(passwd_to_null, "\0\0\0"), "The password has not been zeroed. Instead it was:\"" << passwd << "\".");

	const cJSON *response4 = credentials_ok(user_no_passwd, passwd_to_null);
	BOOST_CHECK_MESSAGE(response4 == NULL, "Response should be NULL when no password is given in the user database.");

	const cJSON *response5 = credentials_ok(user_passwd_no_string, passwd_to_null);
	BOOST_CHECK_MESSAGE(response5 == NULL, "Response should be NULL when password in database is not a string.");

	const cJSON *response6 = credentials_ok(unknown_user, passwd_to_null);
	BOOST_CHECK_MESSAGE(response6 == NULL, "Response should be NULL when password in database is not a string.");

	const cJSON *response7 = credentials_ok(username, passwd);
	BOOST_REQUIRE_MESSAGE(response7 != NULL, "User authentication failed even with correct credentials.");
}

BOOST_AUTO_TEST_CASE(check_credentials_no_user_data_loaded)
{
	char username[] = "john";
	char passwd[] = "doe";

	const cJSON *response1 = credentials_ok(username, passwd);
	BOOST_CHECK_MESSAGE(response1 == NULL, "Response should be NULL when no user data is loaded in before.");
}

BOOST_FIXTURE_TEST_CASE(change_credentials, F)
{
	char username[] = "john";
	char username_ro[] = "john-ro";
	char username_admin[] = "john-admin";
	char username_not_in_db[] = "mister_x";
	char username_no_password[] = "bob_read_only";
	char username_pw_no_string[] = "john-pw_no_string";
	char username_bob[] = "bob";
	char old_passwd[] = "doe";
	char new_passwd[] = "secret";

	cJSON *fake_request = cJSON_CreateObject();
	cJSON *id = cJSON_CreateNumber(123);
	cJSON_AddItemToObject(fake_request, "id", id);
	struct peer *test_peer = alloc_peer();

	test_peer->user_name = NULL;
	cJSON *response = change_password(test_peer, fake_request, username, new_passwd);
	BOOST_REQUIRE_MESSAGE(response != NULL, "The response for changing a password should never be null.");
	BOOST_CHECK_MESSAGE(response_is_error(response), "Peer could change password, even without beeing authenticated.");
	cJSON_Delete(response);

	std::strcpy(new_passwd, "secret");
	test_peer->user_name = username_not_in_db;
	response = change_password(test_peer, fake_request, username_not_in_db, new_passwd);
	BOOST_REQUIRE_MESSAGE(response != NULL, "The response for changing a password should never be null.");
	BOOST_CHECK_MESSAGE(response_is_error(response), "User can change password, without beeing stored in database.");
	cJSON_Delete(response);

	std::strcpy(new_passwd, "secret");
	test_peer->user_name = username_pw_no_string;
	response = change_password(test_peer, fake_request, username_pw_no_string, new_passwd);
	BOOST_REQUIRE_MESSAGE(response != NULL, "The response for changing a password should never be null.");
	BOOST_CHECK_MESSAGE(response_is_error(response), "User can change password, even if it is not a string.");
	cJSON_Delete(response);

	std::strcpy(new_passwd, "secret");
	test_peer->user_name = username_no_password;
	response = change_password(test_peer, fake_request, username_no_password, new_passwd);
	BOOST_REQUIRE_MESSAGE(response != NULL, "The response for changing a password should never be null.");
	BOOST_CHECK_MESSAGE(response_is_error(response), "User can change password, without having a password assigned.");
	cJSON_Delete(response);

	std::strcpy(new_passwd, "secret");
	test_peer->user_name = username;
	response = change_password(test_peer, fake_request, username, new_passwd);
	BOOST_REQUIRE_MESSAGE(response != NULL, "The response for changing a password should never be null.");
	if (response_is_error(response)) {
		BOOST_CHECK_MESSAGE(false, "Changing password failed. Error message: " << extract_error_message(response));
	}
	cJSON_Delete(response);

	const cJSON *response1 = credentials_ok(username, old_passwd);
	BOOST_REQUIRE_MESSAGE(response1 == NULL, "User authentication did not fail with old credentials, even after changing password.");

	std::strcpy(new_passwd, "secret");
	const cJSON *response2 = credentials_ok(username, new_passwd);
	BOOST_REQUIRE_MESSAGE(response2 != NULL, "User Authentication failed after changing password.");

	std::strcpy(new_passwd, "secret");
	response = change_password(test_peer, fake_request, username_ro, new_passwd);
	BOOST_CHECK_MESSAGE(response_is_error(response), "Read only user was able to change password");
	cJSON_Delete(response);

	std::strcpy(new_passwd, "secret");
	response = change_password(test_peer, fake_request, username_bob, new_passwd);

	BOOST_CHECK_MESSAGE(response_is_error(response), "User john was able to change bob's password, even without beeing admin.");
	cJSON_Delete(response);

	std::strcpy(new_passwd, "secret");
	test_peer->user_name = username_admin;
	response = change_password(test_peer, fake_request, username_bob, new_passwd);
	if (response_is_error(response)) {
		BOOST_CHECK_MESSAGE(false, "Admin couldn't change other users password." << extract_error_message(response));
	} else {
		strcpy(new_passwd, "secret");
		const cJSON *response3 = credentials_ok(username_bob, new_passwd);
		BOOST_CHECK_MESSAGE(response3 != NULL, "User Authentication failed after admin changed password.");
	}
	cJSON_Delete(response);

	std::strcpy(new_passwd, "secret");
	response = change_password(test_peer, fake_request, username_ro, new_passwd);
	BOOST_CHECK_MESSAGE(response_is_error(response), "Admin could change password of read_only user.");
	cJSON_Delete(response);

	cJSON_Delete(fake_request);
	free_peer(test_peer);
}
