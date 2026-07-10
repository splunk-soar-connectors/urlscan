# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.asset import BaseAsset
from soar_sdk.exceptions import ActionFailure

from ..client import UrlscanClient
from ..constants import (
    URLSCAN_ACTION_SUCCESS,
    URLSCAN_NO_DATA_ERROR,
    URLSCAN_SEARCH_ENDPOINT,
)
from ..outputs import LookupActionOutput, LookupSummary
from ..output_utils import clean_output_data

URLSCAN_SEARCH_RESERVED_CHARS = frozenset('+-=&|><!(){}[]^"~*?:\\/')


def _escape_search_value(value: str) -> str:
    return "".join(
        f"\\{char}" if char.isspace() or char in URLSCAN_SEARCH_RESERVED_CHARS else char
        for char in value
    )


def _run_lookup(asset: BaseAsset, soar: SOARClient, query: str) -> LookupActionOutput:
    client = UrlscanClient.from_asset(asset)
    headers = {"API-Key": client.api_key} if client.api_key else None
    response = client.request(
        URLSCAN_SEARCH_ENDPOINT,
        headers=headers,
        params={"q": query},
    )

    if not response.ok:
        response_data = response.data if isinstance(response.data, dict) else {}
        message = (
            response.message or response_data.get("message") or URLSCAN_NO_DATA_ERROR
        )
        raise ActionFailure(message)

    response_data = response.data if isinstance(response.data, dict) else {}
    results = response_data.get("results")
    soar.set_message(URLSCAN_ACTION_SUCCESS if results else URLSCAN_NO_DATA_ERROR)
    soar.set_summary(LookupSummary(total=response_data.get("total", 0)))
    return LookupActionOutput(**clean_output_data(response_data))


def run_hunt_domain(
    params: Any, soar: SOARClient, asset: BaseAsset
) -> LookupActionOutput:
    return _run_lookup(asset, soar, f"domain:{_escape_search_value(params.domain)}")


def run_hunt_ip(params: Any, soar: SOARClient, asset: BaseAsset) -> LookupActionOutput:
    return _run_lookup(asset, soar, f'ip:"{_escape_search_value(params.ip)}"')
