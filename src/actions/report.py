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
import time
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.asset import BaseAsset
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from ..client import UrlscanClient
from ..constants import (
    URLSCAN_ACTION_SUCCESS,
    URLSCAN_BAD_REQUEST_CODE,
    URLSCAN_MAX_POLLING_ATTEMPTS,
    URLSCAN_NO_DATA_ERROR,
    URLSCAN_NOT_FOUND_CODE,
    URLSCAN_POLL_SUBMISSION_ENDPOINT,
    URLSCAN_POLLING_INTERVAL,
    URLSCAN_REPORT_NOT_FOUND_ERROR,
)
from ..outputs import ReportSummary, UrlscanReportOutput
from ..output_utils import clean_output_data

logger = getLogger()


def poll_submission(
    *,
    report_uuid: str,
    asset: BaseAsset,
    get_result: bool = True,
    request_context: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any] | None, int]:
    client = UrlscanClient.from_asset(asset)
    headers = {"Content-Type": "application/json"}
    if client.api_key:
        headers["API-Key"] = client.api_key

    for polling_attempt in range(1, URLSCAN_MAX_POLLING_ATTEMPTS + 1):
        logger.progress(
            f"Polling attempt {polling_attempt} of {URLSCAN_MAX_POLLING_ATTEMPTS}"
        )

        response = client.request(
            URLSCAN_POLL_SUBMISSION_ENDPOINT.format(report_uuid),
            headers=headers,
        )

        if not response.ok:
            response_data = response.data if isinstance(response.data, dict) else {}
            if response_data.get("status", 0) == URLSCAN_BAD_REQUEST_CODE:
                raise ActionFailure(response.message)
            raise ActionFailure(response.message or URLSCAN_NO_DATA_ERROR)

        response_data = response.data if isinstance(response.data, dict) else {}
        if (
            response_data.get("status", 0) == URLSCAN_NOT_FOUND_CODE
            or response_data.get("message") == "notdone"
        ):
            time.sleep(URLSCAN_POLLING_INTERVAL)
            continue

        if request_context:
            response_data = {**response_data, **request_context}

        if not get_result:
            return URLSCAN_ACTION_SUCCESS, None, 0

        tags = (response_data.get("task", {}) or {}).get("tags", []) or []
        return URLSCAN_ACTION_SUCCESS, response_data, len(tags)

    return URLSCAN_REPORT_NOT_FOUND_ERROR.format(report_uuid), None, 0


def run_get_report(
    params: Any, soar: SOARClient, asset: BaseAsset
) -> UrlscanReportOutput:
    message, report, added_tags_num = poll_submission(
        report_uuid=params.id,
        asset=asset,
    )
    report = report or {}
    task = report.get("task", {}) or {}
    page = report.get("page", {}) or {}

    soar.set_message(message)
    soar.set_summary(
        ReportSummary(
            added_tags_num=added_tags_num,
            report_uuid=params.id,
            scan_uuid=task.get("uuid"),
            page_domain=page.get("domain"),
        )
    )
    return UrlscanReportOutput(**clean_output_data(report))
