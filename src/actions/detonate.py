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

from ..constants import (
    URLSCAN_ACTION_SUCCESS,
    URLSCAN_API_KEY_MISSING_ERROR,
    URLSCAN_BAD_REQUEST_CODE,
    URLSCAN_BAD_REQUEST_ERROR,
    URLSCAN_DETONATE_URL_ENDPOINT,
    URLSCAN_MAX_TAG_LENGTH,
    URLSCAN_MAX_TAGS_NUM,
    URLSCAN_NO_DATA_ERROR,
    URLSCAN_REPORT_UUID_MISSING_ERROR,
    URLSCAN_TAGS_EXCEED_MAX_ERROR,
    URLSCAN_TAGS_OMITTED_NOTICE,
)
from .action_utils import build_action_result, make_client, set_result
from .report import poll_submission
from .screenshot import run_get_screenshot


def _with_tag_feedback(message: str, omitted_tags: list[str]) -> str:
    if not omitted_tags:
        return message
    return (
        f"{message}. "
        f"{URLSCAN_TAGS_OMITTED_NOTICE.format(len(omitted_tags), URLSCAN_MAX_TAG_LENGTH)}"
    )


def run_detonate_url(params: Any, soar: SOARClient, asset: BaseAsset):
    result = build_action_result(params)
    client = make_client(asset)

    if not client.api_key:
        return set_result(result, False, URLSCAN_API_KEY_MISSING_ERROR)

    tags: list[str] = []
    omitted_tags: list[str] = []
    seen_tags: set[str] = set()

    for raw_tag in (params.tags or "").split(","):
        tag = raw_tag.strip()
        if not tag or tag in seen_tags:
            continue
        seen_tags.add(tag)

        if len(tag) > URLSCAN_MAX_TAG_LENGTH:
            omitted_tags.append(tag)
            continue

        tags.append(tag)

    if len(tags) > URLSCAN_MAX_TAGS_NUM:
        return set_result(
            result,
            False,
            URLSCAN_TAGS_EXCEED_MAX_ERROR.format(URLSCAN_MAX_TAGS_NUM),
        )

    payload: dict[str, Any] = {
        "url": params.url,
        "public": "off" if params.private else "on",
        "tags": tags,
    }
    if params.custom_agent:
        payload["customagent"] = params.custom_agent

    response = client.request(
        URLSCAN_DETONATE_URL_ENDPOINT,
        method="post",
        headers={"Content-Type": "application/json", "API-Key": client.api_key},
        json_data=payload,
    )

    if not response.ok:
        response_data = response.data if isinstance(response.data, dict) else {}
        if response_data.get("status", 0) == URLSCAN_BAD_REQUEST_CODE:
            response_data = {
                **response_data,
                "submitted_tags": tags,
                "omitted_tags": omitted_tags,
                "omitted_tags_num": len(omitted_tags),
            }
            return set_result(
                result,
                True,
                _with_tag_feedback(
                    URLSCAN_BAD_REQUEST_ERROR.format(
                        response_data.get("message", "None"),
                        response_data.get("description", "None"),
                    ),
                    omitted_tags,
                ),
                data=response_data,
                summary={
                    "added_tags_num": len(tags),
                    "omitted_tags_num": len(omitted_tags),
                },
            )
        return set_result(result, False, response.message or URLSCAN_NO_DATA_ERROR)

    response_data = response.data if isinstance(response.data, dict) else {}
    report_uuid = response_data.get("uuid")
    if not report_uuid:
        return set_result(result, False, URLSCAN_REPORT_UUID_MISSING_ERROR)

    request_context = {
        "requested_url": params.url,
        "requested_get_result": params.get_result,
        "submitted_tags": tags,
        "omitted_tags": omitted_tags,
        "omitted_tags_num": len(omitted_tags),
    }

    if params.get_result or params.addto_vault:
        submission = poll_submission(
            report_uuid=report_uuid,
            result=result,
            asset=asset,
            get_result=params.get_result,
            request_context=request_context,
        )
        if not submission.get_status():
            return submission

        if omitted_tags:
            submission.set_status(
                submission.get_status(),
                _with_tag_feedback(submission.get_message(), omitted_tags),
            )
            submission.set_summary(
                {
                    **submission.get_summary(),
                    "omitted_tags_num": len(omitted_tags),
                }
            )

        if params.addto_vault:
            screenshot_result = run_get_screenshot(
                params,
                soar,
                asset,
                report_id=report_uuid,
                container_id=getattr(params, "container_id", None),
            )
            if not screenshot_result.get_status():
                return screenshot_result

            submission.set_status(
                screenshot_result.get_status(),
                _with_tag_feedback(screenshot_result.get_message(), omitted_tags),
            )
            submission.set_summary(
                {
                    **submission.get_summary(),
                    **screenshot_result.get_summary(),
                }
            )

        return submission

    response_data = {**response_data, **request_context}
    summary: dict[str, Any] = {"added_tags_num": len(tags)}
    if omitted_tags:
        summary["omitted_tags_num"] = len(omitted_tags)
    return set_result(
        result,
        True,
        _with_tag_feedback(URLSCAN_ACTION_SUCCESS, omitted_tags),
        data=response_data,
        summary=summary,
    )
