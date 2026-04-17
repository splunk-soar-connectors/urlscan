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
import logging
from dataclasses import dataclass
from typing import Any

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

try:
    from .constants import (
        URLSCAN_BASE_URL,
        URLSCAN_EMPTY_RESPONSE_ERROR,
        URLSCAN_ERROR_CODE_UNAVAILABLE,
        URLSCAN_ERROR_MESSAGE_UNAVAILABLE,
        URLSCAN_FILE_RESPONSE_ERROR,
        URLSCAN_HTML_RESPONSE_ERROR,
        URLSCAN_JSON_RESPONSE_PARSE_ERROR,
        URLSCAN_JSON_RESPONSE_SERVER_ERROR,
        URLSCAN_NOT_FOUND_CODE,
        URLSCAN_PROCESS_RESPONSE_ERROR,
        URLSCAN_SERVER_CONNECTIVITY_ERROR,
    )
except ImportError:
    from constants import (
        URLSCAN_BASE_URL,
        URLSCAN_EMPTY_RESPONSE_ERROR,
        URLSCAN_ERROR_CODE_UNAVAILABLE,
        URLSCAN_ERROR_MESSAGE_UNAVAILABLE,
        URLSCAN_FILE_RESPONSE_ERROR,
        URLSCAN_HTML_RESPONSE_ERROR,
        URLSCAN_JSON_RESPONSE_PARSE_ERROR,
        URLSCAN_JSON_RESPONSE_SERVER_ERROR,
        URLSCAN_NOT_FOUND_CODE,
        URLSCAN_PROCESS_RESPONSE_ERROR,
        URLSCAN_SERVER_CONNECTIVITY_ERROR,
    )


@dataclass
class UrlscanResponse:
    ok: bool
    data: Any | None
    message: str = ""
    response: httpx.Response | None = None


class UrlscanClient:
    def __init__(self, api_key: str | None, timeout: float | None) -> None:
        self.api_key = api_key or ""
        self.timeout = timeout or 120.0

    def _get_error_message_from_exception(self, exc: Exception) -> str:
        error_code = URLSCAN_ERROR_CODE_UNAVAILABLE
        error_message = URLSCAN_ERROR_MESSAGE_UNAVAILABLE

        if exc.args:
            if len(exc.args) > 1:
                error_code = str(exc.args[0])
                error_message = str(exc.args[1])
            else:
                error_message = str(exc.args[0])

        return f"Error Code: {error_code}. Error Message: {error_message}"

    def _process_empty_response(self, response: httpx.Response) -> UrlscanResponse:
        if response.status_code == 200:
            return UrlscanResponse(True, {})
        return UrlscanResponse(
            False, None, URLSCAN_EMPTY_RESPONSE_ERROR.format(response.status_code)
        )

    def _process_file_response(self, response: httpx.Response) -> UrlscanResponse:
        if response.status_code == 200:
            return UrlscanResponse(True, None, response=response)
        return UrlscanResponse(
            False, None, URLSCAN_FILE_RESPONSE_ERROR.format(response.status_code)
        )

    def _process_html_response(self, response: httpx.Response) -> UrlscanResponse:
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = "\n".join(
                line.strip() for line in soup.text.splitlines() if line.strip()
            )
        except (TypeError, ValueError, AttributeError):
            logger.warning("Failed to parse HTML error response", exc_info=True)
            error_text = "Cannot parse error details"

        return UrlscanResponse(
            False,
            None,
            URLSCAN_HTML_RESPONSE_ERROR.format(response.status_code, error_text),
        )

    def _process_json_response(self, response: httpx.Response) -> UrlscanResponse:
        try:
            response_json = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            error_message = self._get_error_message_from_exception(exc)
            return UrlscanResponse(
                False, None, URLSCAN_JSON_RESPONSE_PARSE_ERROR.format(error_message)
            )

        if 200 <= response.status_code < 399:
            return UrlscanResponse(True, response_json, response=response)

        if response_json.get("status") == URLSCAN_NOT_FOUND_CODE:
            return UrlscanResponse(True, response_json, response=response)

        return UrlscanResponse(
            False,
            response_json,
            URLSCAN_JSON_RESPONSE_SERVER_ERROR.format(
                response.status_code, response.text
            ),
            response=response,
        )

    def _process_response(self, response: httpx.Response) -> UrlscanResponse:
        content_type = response.headers.get("Content-Type", "")

        if "json" in content_type:
            return self._process_json_response(response)

        if "html" in content_type:
            return self._process_html_response(response)

        if "image" in content_type or "octet-stream" in content_type:
            return self._process_file_response(response)

        if not response.text:
            return self._process_empty_response(response)

        return UrlscanResponse(
            False,
            None,
            URLSCAN_PROCESS_RESPONSE_ERROR.format(response.status_code, response.text),
            response=response,
        )

    def request(
        self,
        endpoint: str,
        *,
        method: str = "get",
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> UrlscanResponse:
        request_headers = headers.copy() if headers else {}

        try:
            with httpx.Client(
                base_url=URLSCAN_BASE_URL,
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                response = client.request(
                    method.upper(),
                    endpoint,
                    headers=request_headers or None,
                    params=params,
                    json=json_data,
                )
        except httpx.HTTPError as exc:
            error_message = self._get_error_message_from_exception(exc)
            return UrlscanResponse(
                False, None, URLSCAN_SERVER_CONNECTIVITY_ERROR.format(error_message)
            )

        return self._process_response(response)
