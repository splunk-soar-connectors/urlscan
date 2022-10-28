# File: urlscan_consts.py
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
# Constants
URLSCAN_BASE_URL = "https://urlscan.io/api/v1/"
URLSCAN_MAX_POLLING_ATTEMPTS = 10
URLSCAN_POLLING_INTERVAL = 15
URLSCAN_MAX_TAGS_NUM = 10
URLSCAN_BAD_REQUEST_CODE = 400
URLSCAN_NOT_FOUND_CODE = 404

# Endpoints
URLSCAN_HUNT_DOMAIN_ENDPOINT = "search/?q=domain:{}"
URLSCAN_HUNT_IP_ENDPOINT = 'search/?q=ip:"{}"'
URLSCAN_POLL_SUBMISSION_ENDPOINT = "result/{}"
URLSCAN_DETONATE_URL_ENDPOINT = "scan/"

# Status messages
URLSCAN_ERR_CODE_UNAVAILABLE = "Error code unavailable"
URLSCAN_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or the action parameters."
URLSCAN_EMPTY_RESPONSE_ERR = "Status code: {}. Empty response and no information in the header"
URLSCAN_HTML_RESPOSE_ERR = "Status Code: {0}. Data from server: {1}"
URLSCAN_JSON_RESPONSE_PARSE_ERR = "Unable to parse JSON response. Error: {}"
URLSCAN_JSON_RESPONSE_SERVER_ERR = "Error from server. Status Code: {0}. Data from server: {1}"
URLSCAN_PROCESS_RESPONSE_ERR = "Can't process response from server. Status Code: {0} Data from server: {1}"
URLSCAN_SERVER_CONNECTION_ERR = "Error Connecting to server. Details: {}"
URLSCAN_TEST_CONNECTIVITY_ERR = "Test Connectivity Failed"
URLSCAN_TEST_CONNECTIVITY_SUCC = "Test Connectivity Passed"
URLSCAN_API_KEY_MISSING_ERR = "API Key is required to run detonate url"  # pragma: allowlist secret
URLSCAN_REPORT_UUID_MISSING_ERR = "Unable to get report UUID from scan"
URLSCAN_BAD_REQUEST_ERR = "Error: {0}. Description: {1}"
URLSCAN_NO_DATA_ERR = "No data found"
URLSCAN_REPORT_NOT_FOUND_ERR = "Report not found, report uuid: {}"
URLSCAN_TAGS_EXCEED_MAX_ERR = "The number of tags attached to the scan has exceeded the max limit {}"
URLSCAN_ACTION_SUCC = "Successfully retrieved information"

# Action names
URLSCAN_TEST_CONNECTIVITY_ACTION = "test_connectivity"
URLSCAN_GET_REPORT_ACTION = "get_report"
URLSCAN_HUNT_DOMAIN_ACTION = "hunt_domain"
URLSCAN_HUNT_IP_ACTION = "hunt_ip"
URLSCAN_DETONATE_URL_ACTION = "detonate_url"
