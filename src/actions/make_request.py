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
import json
from typing import Any

import httpx
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.asset import BaseAsset
from soar_sdk.exceptions import ActionFailure

from ..client import UrlscanClient
from ..constants import URLSCAN_BASE_URL
from ..params import UrlscanMakeRequestParams


def run_make_request(
    params: UrlscanMakeRequestParams, asset: BaseAsset
) -> MakeRequestOutput:
    """Execute an arbitrary HTTP request against a urlscan.io API endpoint."""
    endpoint = params.endpoint.strip().lstrip("/")
    if not endpoint:
        raise ActionFailure("The endpoint parameter is required.")

    if endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            "Do not include the base URL in the endpoint. "
            "Only the path is needed, e.g. 'api/v1/search/?q=domain:example.com'."
        )

    client_obj = UrlscanClient.from_asset(asset)
    timeout = params.timeout if params.timeout else client_obj.timeout

    request_headers: dict[str, str] = {}
    if client_obj.api_key:
        request_headers["API-Key"] = client_obj.api_key

    if params.headers:
        try:
            extra_headers = json.loads(params.headers)
            if not isinstance(extra_headers, dict):
                raise ActionFailure("The headers parameter must be a JSON object.")
            request_headers.update(extra_headers)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ActionFailure(
                f"Invalid JSON in the headers parameter: {params.headers}"
            ) from exc

    request_url = f"{URLSCAN_BASE_URL}/{endpoint}"
    request_kwargs: dict[str, Any] = {
        "method": params.http_method,
        "url": request_url,
        "headers": request_headers,
        "timeout": timeout,
        "follow_redirects": True,
    }

    if params.query_parameters:
        try:
            parsed_params = json.loads(params.query_parameters)
            if not isinstance(parsed_params, dict):
                raise ActionFailure(
                    "The query_parameters parameter must be a JSON object."
                )
            request_kwargs["params"] = parsed_params
        except (json.JSONDecodeError, TypeError):
            query_string = params.query_parameters.lstrip("?")
            sep = "&" if "?" in endpoint else "?"
            request_kwargs["url"] = f"{request_url}{sep}{query_string}"

    if params.body:
        try:
            parsed_body = json.loads(params.body)
            request_kwargs["json"] = parsed_body
        except (json.JSONDecodeError, TypeError) as exc:
            raise ActionFailure(
                f"Invalid JSON in the body parameter: {params.body}"
            ) from exc

    try:
        with httpx.Client(verify=params.verify_ssl) as http_client:
            response = http_client.request(**request_kwargs)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise ActionFailure(
            f"Request failed with status {exc.response.status_code}: {exc.response.text}"
        ) from exc
    except httpx.HTTPError as exc:
        raise ActionFailure(f"HTTP request failed: {exc}") from exc

    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response.text,
    )
