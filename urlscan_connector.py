# File: urlscan_connector.py
#
# Copyright (c) 2017-2025 Splunk Inc.
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
import mimetypes
import os
import tempfile
import time
import traceback

import magic
import phantom.app as phantom
import phantom.rules as ph_rules
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault as Vault
from phantom_common import paths

from urlscan_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class UrlscanConnector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = URLSCAN_BASE_URL
        self._api_key = None
        self.timeout = None

    def _dump_error_log(self, error, message="Exception occurred."):
        self.error_print(message, dump_object=error)

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_code = URLSCAN_ERROR_CODE_UNAVAILABLE
        error_message = URLSCAN_ERROR_MESSAGE_UNAVAILABLE
        self.error_print(f"Traceback: {traceback.format_stack()}")
        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
        except Exception as ex:
            self._dump_error_log(ex, "Error occurred while fetching exception information")

        return f"Error Code: {error_code}. Error Message: {error_message}"

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})
        return RetVal(action_result.set_status(phantom.APP_ERROR, URLSCAN_EMPTY_RESPONSE_ERROR.format(response.status_code)), None)

    def _process_file_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, response)
        return RetVal(action_result.set_status(phantom.APP_ERROR, URLSCAN_FILE_RESPONSE_ERROR.format(response.status_code)), None)

    def _process_html_response(self, response, action_result):
        # A html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = URLSCAN_HTML_RESPONSE_ERROR.format(status_code, error_text)

        message = message.replace("{", "{{").replace("}", "}}")

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, URLSCAN_JSON_RESPONSE_PARSE_ERROR.format(error_message)), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        try:
            # The server should return a 404 if a scan isn't finished yet
            if resp_json["status"] == URLSCAN_NOT_FOUND_CODE:
                return RetVal(phantom.APP_SUCCESS, resp_json)
        except KeyError:
            self.debug_print("Error occurred while retrieving status_code")

        # You should process the error returned in the json
        message = URLSCAN_JSON_RESPONSE_SERVER_ERROR.format(r.status_code, r.text.replace("{", "{{").replace("}", "}}"))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        if "image" in r.headers.get("Content-Type", "") or "octet-stream" in r.headers.get("Content-Type", ""):
            return self._process_file_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = URLSCAN_PROCESS_RESPONSE_ERROR.format(r.status_code, r.text.replace("{", "{{").replace("}", "}}"))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):
        config = self.get_config()

        resp_json = None
        request_func = getattr(requests, method)

        if not request_func:
            action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}")

        # Create a URL to connect to
        url = f"{self._base_url}{endpoint}"

        try:
            r = request_func(
                url, json=data, headers=headers, verify=config.get("verify_server_cert", False), params=params, timeout=self.timeout
            )
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, URLSCAN_SERVER_CONNECTIVITY_ERROR.format(error_message)), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if self._api_key:
            self.save_progress("Validating API Key")
            headers = {"API-Key": self._api_key}
            ret_val, response = self._make_rest_call(URLSCAN_TEST_CONNECTIVITY_ENDPOINT, action_result, headers=headers)
        else:
            self.save_progress("No API key found, checking connectivity to urlscan.io")
            ret_val, response = self._make_rest_call(URLSCAN_TEST_CONNECTIVITY_ENDPOINT, action_result)

        if phantom.is_fail(ret_val):
            self.save_progress(URLSCAN_TEST_CONNECTIVITY_ERROR)
            return action_result.get_status()

        # Return success
        self.save_progress(URLSCAN_TEST_CONNECTIVITY_SUCCESS)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_report(self, param):
        self.debug_print(f"In action handler for {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        result_id = param["id"]

        self.debug_print("Calling the _poll_submission to fetch the results")

        return self._poll_submission(result_id, action_result)

    def _handle_hunt_domain(self, param):
        self.debug_print(f"In action handler for {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))
        headers = {"API-Key": self._api_key}
        domain = param["domain"]

        ret_val, response = self._make_rest_call(URLSCAN_HUNT_DOMAIN_ENDPOINT.format(domain), action_result, params=None, headers=headers)

        if phantom.is_fail(ret_val):
            if not action_result.get_message():
                error_msg = response.get("message") or URLSCAN_NO_DATA_ERROR
                self.debug_print(error_msg)
                return action_result.set_status(phantom.APP_ERROR, error_msg)
            return action_result.get_status()

        action_result.add_data(response)

        if response.get("results"):
            return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_ACTION_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_NO_DATA_ERROR)

    def _handle_hunt_ip(self, param):
        self.debug_print(f"In action handler for {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        ip = param["ip"]
        headers = {"API-Key": self._api_key}
        ret_val, response = self._make_rest_call(URLSCAN_HUNT_IP_ENDPOINT.format(ip), action_result, params=None, headers=headers)

        if phantom.is_fail(ret_val):
            if not action_result.get_message():
                error_msg = response.get("message") or URLSCAN_NO_DATA_ERROR
                self.debug_print(error_msg)
                return action_result.set_status(phantom.APP_ERROR, error_msg)
            return action_result.get_status()

        action_result.add_data(response)

        if response.get("results"):
            return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_ACTION_SUCCESS)
        else:
            return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_NO_DATA_ERROR)

    def replace_null_values(self, data):
        return json.loads(json.dumps(data).replace("\\u0000", "\\\\u0000"))

    def _poll_submission(self, report_uuid, action_result, get_result=True):
        polling_attempt = 0
        resp_json = None
        headers = {"Content-Type": "application/json", "API-Key": self._api_key}

        while polling_attempt < URLSCAN_MAX_POLLING_ATTEMPTS:
            polling_attempt += 1

            self.send_progress(f"Polling attempt {polling_attempt} of {URLSCAN_MAX_POLLING_ATTEMPTS}")
            self.debug_print(f"Polling attempt {polling_attempt} of {URLSCAN_MAX_POLLING_ATTEMPTS}")

            ret_val, resp_json = self._make_rest_call(URLSCAN_POLL_SUBMISSION_ENDPOINT.format(report_uuid), action_result, headers=headers)

            if phantom.is_fail(ret_val):
                if resp_json and resp_json.get("status", 0) == URLSCAN_BAD_REQUEST_CODE:
                    message = URLSCAN_JSON_RESPONSE_SERVER_ERROR.format(
                        resp_json["status"], json.dumps(resp_json).replace("{", "{{").replace("}", "}}")
                    )
                    return action_result.set_status(phantom.APP_ERROR, message)

                return action_result.get_status()
            # Scan isn't finished yet
            if resp_json.get("status", 0) == URLSCAN_NOT_FOUND_CODE or resp_json.get("message") == "notdone":
                time.sleep(URLSCAN_POLLING_INTERVAL)
                continue

            if not get_result:
                return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_ACTION_SUCCESS)

            resp_json_task = resp_json.get("task", {})
            action_result.update_summary({"added_tags_num": len(resp_json_task.get("tags", []))})
            action_result.add_data(resp_json)
            action_result._ActionResult__data = self.replace_null_values(action_result._ActionResult__data)
            return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_ACTION_SUCCESS)

        return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_REPORT_NOT_FOUND_ERROR.format(report_uuid))

    def _handle_detonate_url(self, param):
        self.debug_print(f"In action handler for {self.get_action_identifier()}")

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        if not self._api_key:
            return action_result.set_status(phantom.APP_ERROR, URLSCAN_API_KEY_MISSING_ERROR)

        url_to_scan = param["url"]
        private = param.get("private", False)
        custom_agent = param.get("custom_agent")
        get_result = param.get("get_result", True)
        addto_vault = param.get("addto_vault", False)  # Add screenshot to vault (default False to keep original behavior)

        # Parse tags
        tags = param.get("tags", "")
        tags = [tags.strip() for tags in tags.split(",")]
        tags = list(set(filter(None, tags)))  # non-duplicate tags

        if len(tags) > URLSCAN_MAX_TAGS_NUM:
            return action_result.set_status(phantom.APP_ERROR, URLSCAN_TAGS_EXCEED_MAX_ERROR.format(URLSCAN_MAX_TAGS_NUM))

        headers = {"Content-Type": "application/json", "API-Key": self._api_key}
        data = {"url": url_to_scan, "public": "off" if private else "on", "tags": tags}

        if custom_agent:
            data["customagent"] = custom_agent

        # make rest call
        ret_val, response = self._make_rest_call(URLSCAN_DETONATE_URL_ENDPOINT, action_result, headers=headers, data=data, method="post")

        if phantom.is_fail(ret_val):
            if response and response.get("status", 0) == URLSCAN_BAD_REQUEST_CODE:
                action_result.add_data(response)
                return action_result.set_status(
                    phantom.APP_SUCCESS, URLSCAN_BAD_REQUEST_ERROR.format(response.get("message", "None"), response.get("description", "None"))
                )

            return action_result.get_status()

        report_uuid = response.get("uuid")
        if not report_uuid:
            return action_result.set_status(phantom.APP_ERROR, URLSCAN_REPORT_UUID_MISSING_ERROR)

        if get_result or addto_vault:
            submission = self._poll_submission(report_uuid, action_result, get_result)
            if phantom.is_fail(submission):
                return action_result.get_status()

            if addto_vault:
                param["report_id"] = report_uuid
                screenshot = self._get_screenshot(action_result, param)
                if phantom.is_fail(screenshot):
                    return action_result.get_status()

            if get_result:
                return submission

        action_result.add_data(response)
        action_result._ActionResult__data = self.replace_null_values(action_result._ActionResult__data)
        action_result.update_summary({})
        return action_result.set_status(phantom.APP_SUCCESS, URLSCAN_ACTION_SUCCESS)

    def _get_screenshot(self, action_result, param):
        try:
            ret_val, response = self._make_rest_call(
                URLSCAN_SCREENSHOT_ENDPOINT.format(param["report_id"]), action_result, params=None, headers=None
            )
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to grab screenshot Error : {e}")

        container_id = param.get("container_id", self.get_container_id())

        vault_add = self._add_file_to_vault(
            action_result=action_result, report_id=param["report_id"], container_id=container_id, response=response
        )

        if phantom.is_fail(vault_add):
            return action_result.get_status()

        return vault_add

    def _handle_get_screenshot(self, param):
        self.debug_print(f"In action handler for {self.get_action_identifier()}")

        action_result = self.add_action_result(ActionResult(dict(param)))

        return self._get_screenshot(action_result=action_result, param=param)

    def _add_file_to_vault(self, action_result, report_id, container_id, response):
        file_name = report_id
        ret_val, container_id = self._validate_integer(action_result, container_id, "container_id")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not hasattr(Vault, "get_vault_tmp_dir"):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = os.path.join(paths.PHANTOM_VAULT, "tmp")

        try:
            file_type = magic.Magic(mime=True).from_buffer(response.content)
            extension = mimetypes.guess_extension(file_type)
        except Exception as e:
            self.save_progress(f"Error determining file types: {e}")
            extension = None

        file_path = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=extension, prefix="tmp_", delete=False).name

        try:
            # open and download the file
            with open(file_path, "wb") as f:
                f.write(response.content)

            file_name = file_name + extension

            # move the file to the vault
            success, msg, vault_id = ph_rules.vault_add(
                container=container_id,
                file_location=file_path,
                file_name=file_name,
            )
            if not success:
                return action_result.set_status(phantom.APP_ERROR, f"Error adding file to the vault, Error: {msg}")

            _, _, vault_meta_info = ph_rules.vault_info(container_id=container_id, vault_id=vault_id)

            if not vault_meta_info:
                return action_result.set_status(phantom.APP_ERROR, "Could not find meta information of the downloaded screenshot's Vault")

            summary = {
                phantom.APP_JSON_VAULT_ID: vault_id,
                phantom.APP_JSON_NAME: file_name,
                "file_type": file_type,
                "id": vault_meta_info[0]["id"],
                "container_id": vault_meta_info[0]["container_id"],
                phantom.APP_JSON_SIZE: vault_meta_info[0][phantom.APP_JSON_SIZE],
            }
            action_result.update_summary(summary)

            return action_result.set_status(phantom.APP_SUCCESS, f"Screenshot downloaded successfully in container : {container_id}")

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, f"Failed to download screenshot in Vault. Error : {e}")

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

        elif action_id == URLSCAN_GET_SCREENSHOT_ACTION:
            ret_val = self._handle_get_screenshot(param)

        return ret_val

    def _validate_integer(self, action_result, parameter, key, allow_zero=False, allow_negative=False):
        """Check if the provided input parameter value is valid.

        :param action_result: Action result or BaseConnector object
        :param parameter: Input parameter value
        :param key: Input parameter key
        :param allow_zero: Zero is allowed or not (default True)
        :param allow_negative: Negative values are allowed or not (default False)
        :returns: phantom.APP_SUCCESS/phantom.APP_ERROR and parameter value itself.
        """
        try:
            if not float(parameter).is_integer():
                return action_result.set_status(phantom.APP_ERROR, ERROR_INVALID_INT_PARAM.format(key=key)), None

            parameter = int(parameter)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, ERROR_INVALID_INT_PARAM.format(key=key)), None

        if not allow_zero and parameter == 0:
            return action_result.set_status(phantom.APP_ERROR, ERROR_ZERO_INT_PARAM.format(key=key)), None
        if not allow_negative and parameter < 0:
            return action_result.set_status(phantom.APP_ERROR, ERROR_NEG_INT_PARAM.format(key=key)), None

        return phantom.APP_SUCCESS, parameter

    def _is_ip(self, input_ip_address):
        """Function that checks given address and return True if address is valid IPv4 or IPV6 address.

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
        self._api_key = config.get("api_key", "")
        self.timeout = config.get("timeout", 120)
        self.set_validator("ipv6", self._is_ip)

        if self._api_key is None:
            self.debug_print("No API key found, setting to empty string")
            self._api_key = ""

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    from sys import argv, exit

    import pudb

    pudb.set_trace()

    if len(argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = UrlscanConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
