# File: urlscan_connector.py
#
# Copyright (c) 2017-2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
import ipaddress
import json
import time
from sys import exit

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from urlscan_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class UrlscanConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(UrlscanConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = URLSCAN_BASE_URL
        self._api_key = None
        self.timeout = None

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = URLSCAN_ERR_CODE_UNAVAILABLE
        error_msg = URLSCAN_ERR_MSG_UNAVAILABLE

        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception:
            self.debug_print("Error occurred while retrieving exception information")

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, URLSCAN_EMPTY_RESPONSE_ERR.format(response.status_code)), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = URLSCAN_HTML_RESPOSE_ERR.format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, URLSCAN_JSON_RESPONSE_PARSE_ERR.format(error_msg)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        try:
            # This is for test connectivity, so we can test the API key
            #  without needing to create a token
            if resp_json["status"] == 400:
                return RetVal(phantom.APP_ERROR, resp_json)

            # The server should return a 404 if a scan isn't finished yet
            if resp_json["status"] == 404:
                return RetVal(phantom.APP_SUCCESS, resp_json)
        except KeyError:
            self.debug_print("Error occurred while retrieving status_code")

        # You should process the error returned in the json
        message = URLSCAN_JSON_RESPONSE_SERVER_ERR.format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = URLSCAN_PROCESS_RESPONSE_ERR.format(r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None
        request_func = getattr(requests, method)

        if not request_func:
            action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method))

        # Create a URL to connect to
        url = "{}{}".format(self._base_url, endpoint)

        try:
            r = request_func(
                            url,
                            json=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params,
                            timeout=self.timeout)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, URLSCAN_SERVER_CONNECTION_ERR.format(error_msg)), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._api_key:
            self.save_progress("Validating API Key")
            headers = {'API-Key': self._api_key}
            data = {'url': 'aaaa', 'public': 'off'}
            ret_val, response = self._make_rest_call(URLSCAN_DETONATE_URL_ENDPOINT, action_result, headers=headers, data=data, method="post")
        else:
            self.save_progress("No API key found, checking connectivity to urlscan.io")
            ret_val, response = self._make_rest_call(URLSCAN_HUNT_DOMAIN_ENDPOINT.format('urlscan.io'), action_result)

        if phantom.is_fail(ret_val):
            # 400 is indicative of a malformed request, which we intentionally send to avoid starting a scan
            # If the API Key was invalid, it would return a 401
            if not response or (self._api_key and response.get('status', 0) != 400):
                self.save_progress(URLSCAN_TEST_CONNECTIVITY_ERR)
                return action_result.get_status()

        # Return success
        self.save_progress(URLSCAN_TEST_CONNECTIVITY_SUCC)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):

        self.debug_print("In action handler for {}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        result_id = param['id']

        self.debug_print("Calling the _poll_submission to fetch the results")

        return self._poll_submission(result_id, action_result)

    def _handle_hunt_domain(self, param):

        self.debug_print("In action handler for {}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']

        ret_val, response = self._make_rest_call(URLSCAN_HUNT_DOMAIN_ENDPOINT.format(domain), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            if not action_result.get_message():
                error_msg = response.get('message') or URLSCAN_NO_DATA_ERR
                self.debug_print(error_msg)
                return action_result.set_status(phantom.APP_ERROR, error_msg)
            return action_result.get_status()

        action_result.add_data(response)

        if response.get('results'):
            return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_ACTION_SUCC)
        else:
            return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_NO_DATA_ERR)

    def _handle_hunt_ip(self, param):

        self.debug_print("In action handler for {}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']

        ret_val, response = self._make_rest_call(URLSCAN_HUNT_IP_ENDPOINT.format(ip), action_result, params=None, headers=None)

        if phantom.is_fail(ret_val):
            if not action_result.get_message():
                error_msg = response.get('message') or URLSCAN_NO_DATA_ERR
                self.debug_print(error_msg)
                return action_result.set_status(phantom.APP_ERROR, error_msg)
            return action_result.get_status()

        action_result.add_data(response)

        if response.get('results'):
            return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_ACTION_SUCC)
        else:
            return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_NO_DATA_ERR)

    def _poll_submission(self, report_uuid, action_result):

        polling_attempt = 0
        resp_json = None
        headers = {'Content-Type': 'application/json', 'API-Key': self._api_key}

        while polling_attempt < URLSCAN_MAX_POLLING_ATTEMPTS:

            polling_attempt += 1

            self.send_progress("Polling attempt {0} of {1}".format(polling_attempt, URLSCAN_MAX_POLLING_ATTEMPTS))
            self.debug_print("Polling attempt {0} of {1}".format(polling_attempt, URLSCAN_MAX_POLLING_ATTEMPTS))

            ret_val, resp_json = self._make_rest_call(URLSCAN_POLL_SUBMISSION_ENDPOINT.format(report_uuid), action_result, headers=headers)

            if phantom.is_fail(ret_val):
                if resp_json and resp_json.get('status', 0) == 400:
                    message = URLSCAN_JSON_RESPONSE_SERVER_ERR.format(
                        resp_json['status'], json.dumps(resp_json).replace('{', '{{').replace('}', '}}'))
                    return action_result.set_status(phantom.APP_ERROR, message)

                return action_result.get_status()
            # Scan isn't finished yet
            if resp_json.get('status', 0) == 404 or resp_json.get('message') == 'notdone':
                time.sleep(URLSCAN_POLLING_INTERVAL)
                continue

            resp_json_task = resp_json.get('task', {})
            action_result.update_summary({"added_tags_num": len(resp_json_task.get('tags', []))})
            action_result.add_data(resp_json)
            return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_ACTION_SUCC)

        return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_REPORT_NOT_FOUND_ERR.format(report_uuid))

    def _handle_detonate_url(self, param):

        self.debug_print("In action handler for {}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._api_key:
            return action_result.set_status(phantom.APP_ERROR, URLSCAN_API_KEY_MISSING_ERR)

        url_to_scan = param['url']
        private = param.get('private', False)
        get_result = param.get('get_result', True)

        # Parse tags
        tags = param.get("tags", "")
        tags = [tags.strip() for tags in tags.split(',')]
        tags = list(filter(None, tags))

        if len(tags) > URLSCAN_MAX_TAGS_NUM:
            return action_result.set_status(phantom.APP_ERROR, URLSCAN_TAGS_EXCEED_MAX_ERR.format(URLSCAN_MAX_TAGS_NUM))

        headers = {'Content-Type': 'application/json', 'API-Key': self._api_key}
        data = {"url": url_to_scan, "public": "off" if private else "on", "tags": tags}

        # make rest call
        ret_val, response = self._make_rest_call(URLSCAN_DETONATE_URL_ENDPOINT, action_result, headers=headers, data=data, method="post")

        if phantom.is_fail(ret_val):
            if response and response.get('status', 0) == 400:
                action_result.add_data(response)
                return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_BAD_REQUEST_ERR.format(
                    response.get('message', 'None'), response.get('description', 'None')))

            return action_result.get_status()

        report_uuid = response.get('uuid')
        if not report_uuid:
            return action_result.set_status(phantom.APP_ERROR, URLSCAN_REPORT_UUID_MISSING_ERR)

        if get_result:
            self.debug_print("Fetch the results in the same call")
            return self._poll_submission(report_uuid, action_result)

        action_result.add_data(response)
        action_result.update_summary({})
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == URLSCAN_TEST_CONNECTIVITY_ACTION:
            ret_val = self._handle_test_connectivity(param)

        elif action_id == URLSCAN_GET_REPORT_ACTION:
            ret_val = self._handle_get_report(param)

        elif action_id == URLSCAN_HUNT_DOMAIN_ACTION:
            ret_val = self._handle_hunt_domain(param)

        elif action_id == URLSCAN_HUNT_IP_ACTION:
            ret_val = self._handle_hunt_ip(param)

        elif action_id == URLSCAN_DETONATE_URL_ACTION:
            ret_val = self._handle_detonate_url(param)

        return ret_val

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address
        try:
            ipaddress.ip_address(str(ip_address_input))
        except Exception:
            return False
        return True

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            # There's no need to return the error because the app doesn't save any data in the state file.
            self.debug_print("Resetting the state file with the default format")
            self._state = {"app_version": self.get_app_json().get("app_version")}

        config = self.get_config()
        self._api_key = config.get('api_key')
        self.timeout = config.get('timeout', 120)
        self.set_validator('ipv6', self._is_ip)

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys

    import pudb
    pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = UrlscanConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
