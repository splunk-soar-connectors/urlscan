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

from soar_sdk.action_results import ActionResult
from soar_sdk.asset import BaseAsset

from ..constants import (
    URLSCAN_ACTION_SUCCESS,
    URLSCAN_NO_DATA_ERROR,
    URLSCAN_SEARCH_ENDPOINT,
)
from .action_utils import build_action_result, make_client, set_result

URLSCAN_SEARCH_RESERVED_CHARS = frozenset('+-=&|><!(){}[]^"~*?:\\/')


def _escape_search_value(value: str) -> str:
    return "".join(
        f"\\{char}" if char.isspace() or char in URLSCAN_SEARCH_RESERVED_CHARS else char
        for char in value
    )


def _run_lookup(action_params: Any, asset: BaseAsset, query: str) -> ActionResult:
    result = build_action_result(action_params)
    client = make_client(asset)
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
        return set_result(result, False, message)

    response_data = response.data if isinstance(response.data, dict) else {}
    results = response_data.get("results")
    message = URLSCAN_ACTION_SUCCESS if results else URLSCAN_NO_DATA_ERROR
    return set_result(
        result,
        True,
        message,
        data=response_data,
        summary={"total": response_data.get("total", 0)},
    )


def run_hunt_domain(params: Any, asset: BaseAsset):
    return _run_lookup(params, asset, f"domain:{_escape_search_value(params.domain)}")


def run_hunt_ip(params: Any, asset: BaseAsset):
    return _run_lookup(params, asset, f'ip:"{_escape_search_value(params.ip)}"')
