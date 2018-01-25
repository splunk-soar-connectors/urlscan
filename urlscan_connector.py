# --
# File: urlscan_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from urlscan_consts import *
import time
import requests
import json
from bs4 import BeautifulSoup


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
        self._base_url = "https://urlscan.io/api/v1/"

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

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
            pass

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

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

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None
        request_func = getattr(requests, method)

        if (not request_func):
            action_result.set_status( phantom.APP_ERROR, "Invalid method: {0}".format(method))

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            json=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._api_key:
            self.save_progress("Validating API Key")
            headers = {'API-Key': self._api_key}
            data = {'url': 'aaaa', 'public': 'off'}
            ret_val, response = self._make_rest_call('scan/', action_result, headers=headers, data=data, method="post")
        else:
            self.save_progress("No API key found, checking connectivity to urlscan.io")
            ret_val, response = self._make_rest_call('search/?q=domain:urlscan.io', action_result)

        # 400 is indicative of a malformed request, which we intentionally send to avoid starting a scan
        # If the API Key was invalid, it would return a 401
        if (phantom.is_fail(ret_val)) and (self._api_key and response.get('status', 0) != 400):
            self.save_progress("Test Connectivity Failed. Error: {0}".format(action_result.get_message()))
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        result_id = param['id']

        return self._poll_submission(result_id, action_result)

    def _handle_hunt_domain(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        domain = param['domain']

        ret_val, response = self._make_rest_call('search/?q=domain:{0}'.format(domain), action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_hunt_ip(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param['ip']

        ret_val, response = self._make_rest_call('search/?q=ip:{0}'.format(ip), action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _poll_submission(self, report_uuid, action_result):

        polling_attempt = 0
        max_polling_attempts = 10
        resp_json = None

        while polling_attempt < max_polling_attempts:

            polling_attempt += 1

            self.send_progress("Polling attempt {0} of {1}".format(polling_attempt, max_polling_attempts))

            ret_val, resp_json = self._make_rest_call('result/' + report_uuid, action_result)

            if (phantom.is_fail(ret_val)):
                return ret_val

            # Scan isn't finished yet
            if resp_json.get('status', 0) == 404:
                time.sleep(15)
                continue

            action_result.add_data(resp_json)
            return action_result.set_status(phantom.APP_SUCCESS)

        summary = action_result.update_summary({})
        summary['report_uuid'] = report_uuid
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_detonate_url(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._api_key:
            return action_result.set_status(phantom.APP_ERROR, "API Key is required to run detonate url")

        url_to_scan = param['url']
        private = param.get('private', False)

        headers = {'Content-Type': 'application/json', 'API-Key': self._api_key}
        data = {"url": url_to_scan, "public": "off" if private else "on"}

        # make rest call
        ret_val, response = self._make_rest_call('scan/', action_result, headers=headers, data=data, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        report_uuid = response.get('uuid')
        if (not report_uuid):
            return action_result.set_status(phantom.APP_ERROR, "Unable to get report UUID from scan")

        return self._poll_submission(report_uuid, action_result)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'get_report':
            ret_val = self._handle_get_report(param)

        elif action_id == 'hunt_domain':
            ret_val = self._handle_hunt_domain(param)

        elif action_id == 'hunt_ip':
            ret_val = self._handle_hunt_ip(param)

        elif action_id == 'detonate_url':
            ret_val = self._handle_detonate_url(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        config = self.get_config()
        self._api_key = config.get('api_key')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = UrlscanConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)

