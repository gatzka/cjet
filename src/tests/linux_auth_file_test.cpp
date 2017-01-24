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
#include <iostream> //todo: kann final wieder raus
#include <crypt.h>
#include <stdio.h>

#include "authenticate.h"
#include "json/cJSON.h"


struct F {
	F()
	{
		//TODO Ordner anpassen
		int response = load_passwd_data("/home/ballenthin/Documents/cjet/passwd.json");
		BOOST_REQUIRE_MESSAGE(response == 0,"Loading password file failed.");
	}

	~F()
	{
		free_passwd_data();
//		std::cout << "mach mal pause ^^";

	}

};

BOOST_AUTO_TEST_CASE(check_load_passwd_data_error_paths){
	int response = load_passwd_data(NULL);
	BOOST_CHECK_MESSAGE(response == 0, "Expected 0 as return value when calling load_passwd_data(NULL).");

	response = load_passwd_data("*/___/");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when calling realpath with '*/___/'.");

	response = load_passwd_data("some_non_existing_file_641587976.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening non-existing file.");

	response =load_passwd_data("/home/ballenthin/Documents/cjet/LICENSE");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening non JSON file.");

	//TODO Ordner anpassen
	response =load_passwd_data("/home/ballenthin/Documents/cjet/passwd_no_user_data.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening passwd file without user data.");

	//TODO Ordner anpassen
	response =load_passwd_data("/home/ballenthin/Documents/cjet/passwd_fetch_group_no_array.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening passwd file without array as fetch group.");

	//TODO Ordner anpassen
	response =load_passwd_data("/home/ballenthin/Documents/cjet/passwd_set_group_no_array.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening passwd file without array as set group.");

	//TODO Ordner anpassen
	response =load_passwd_data("/home/ballenthin/Documents/cjet/passwd_call_group_no_array.json");
	BOOST_CHECK_MESSAGE(response == -1, "Error expected when opening passwd file without array as callgroup.");

}

BOOST_AUTO_TEST_CASE(check_clear_password){
//	clear_password(NULL);
}

BOOST_FIXTURE_TEST_CASE(my_name, F)
{

}
