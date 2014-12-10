#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE state

#include <boost/test/unit_test.hpp>

#include "response.h"

BOOST_AUTO_TEST_CASE(boolean_success_false)
{
	cJSON *id = cJSON_CreateString("request1");
	cJSON *response = create_boolean_success_response(id, 0);

	cJSON *result = cJSON_GetObjectItem(response, "result");
	BOOST_CHECK(result->type == cJSON_False);

	cJSON_Delete(id);
	cJSON_Delete(response);
}

BOOST_AUTO_TEST_CASE(boolean_success_true)
{
	cJSON *id = cJSON_CreateString("request1");
	cJSON *response = create_boolean_success_response(id, 1);

	cJSON *result = cJSON_GetObjectItem(response, "result");
	BOOST_CHECK(result->type == cJSON_True);

	cJSON_Delete(id);
	cJSON_Delete(response);
}

BOOST_AUTO_TEST_CASE(boolean_success_true_wrong_id_type)
{
	cJSON *id = cJSON_CreateBool(0);
	cJSON *response = create_boolean_success_response(id, 1);

	BOOST_CHECK(response == NULL);

	cJSON_Delete(id);
}
