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

#include <boost/test/unit_test.hpp>
#include <crypt.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string>

#include "authenticate.h"
#include "json/cJSON.h"

extern "C" {
	int cjet_timer_init(struct cjet_timer *timer, struct eventloop *loop){
		(void) timer;
		(void) loop;
		return 0;
	}

	void cjet_timer_destroy(struct cjet_timer *timer){
		(void) timer;
	}

	void cjet_get_random_bytes(void *bytes, size_t num_bytes)
	{
		BOOST_REQUIRE_MESSAGE(false,"the cjet_get_random_bytes function needs to be implemented, when it is actually used.");
		(void) bytes;
		(void) num_bytes;
	}
}

static std::string create_temp_copy_of_file(std::string source_filename, std::string filename_apendix)
{
	std::string destination_filename(source_filename);
	destination_filename.append(filename_apendix);

	std::ifstream source(source_filename.c_str(), std::ios::binary);
	std::ofstream dest(destination_filename.c_str(), std::ios::binary);

	BOOST_REQUIRE_MESSAGE(source != NULL, "Can't open source file: " << source_filename);
	BOOST_REQUIRE_MESSAGE(dest != NULL, "Can't open destination file: " << destination_filename);
	dest << source.rdbuf();

	source.close();
	dest.close();

	return destination_filename;
}

struct F {
	F()
	{
		int response = load_passwd_data("input_data/passwd_std.json");
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

	response = load_passwd_data("* /___/"); //TODO - leerzeichen
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when calling realpath with '* /___/'.");

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

BOOST_AUTO_TEST_CASE(test_copying)
{
	std::string temporarily_file = create_temp_copy_of_file("input_data/passwd_std.json", "_temp");
}
