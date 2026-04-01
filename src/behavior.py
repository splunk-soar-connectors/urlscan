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
import time
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionResult
from soar_sdk.asset import BaseAsset
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

try:
    from .client import UrlscanClient
    from .constants import (
        ERROR_INVALID_INT_PARAM,
        ERROR_NEG_INT_PARAM,
        ERROR_ZERO_INT_PARAM,
        URLSCAN_ACTION_SUCCESS,
        URLSCAN_API_KEY_MISSING_ERROR,
        URLSCAN_BAD_REQUEST_CODE,
        URLSCAN_BAD_REQUEST_ERROR,
        URLSCAN_DETONATE_URL_ENDPOINT,
        URLSCAN_HUNT_DOMAIN_ENDPOINT,
        URLSCAN_HUNT_IP_ENDPOINT,
        URLSCAN_MAX_POLLING_ATTEMPTS,
        URLSCAN_MAX_TAGS_NUM,
        URLSCAN_NO_DATA_ERROR,
        URLSCAN_NOT_FOUND_CODE,
        URLSCAN_POLL_SUBMISSION_ENDPOINT,
        URLSCAN_POLLING_INTERVAL,
        URLSCAN_REPORT_NOT_FOUND_ERROR,
        URLSCAN_REPORT_UUID_MISSING_ERROR,
        URLSCAN_SCREENSHOT_ENDPOINT,
        URLSCAN_TAGS_EXCEED_MAX_ERROR,
        URLSCAN_TEST_CONNECTIVITY_ENDPOINT,
    )
    from .vault_helpers import add_screenshot_to_vault
except ImportError:
    from client import UrlscanClient
    from constants import (
        ERROR_INVALID_INT_PARAM,
        ERROR_NEG_INT_PARAM,
        ERROR_ZERO_INT_PARAM,
        URLSCAN_ACTION_SUCCESS,
        URLSCAN_API_KEY_MISSING_ERROR,
        URLSCAN_BAD_REQUEST_CODE,
        URLSCAN_BAD_REQUEST_ERROR,
        URLSCAN_DETONATE_URL_ENDPOINT,
        URLSCAN_HUNT_DOMAIN_ENDPOINT,
        URLSCAN_HUNT_IP_ENDPOINT,
        URLSCAN_MAX_POLLING_ATTEMPTS,
        URLSCAN_MAX_TAGS_NUM,
        URLSCAN_NO_DATA_ERROR,
        URLSCAN_NOT_FOUND_CODE,
        URLSCAN_POLL_SUBMISSION_ENDPOINT,
        URLSCAN_POLLING_INTERVAL,
        URLSCAN_REPORT_NOT_FOUND_ERROR,
        URLSCAN_REPORT_UUID_MISSING_ERROR,
        URLSCAN_SCREENSHOT_ENDPOINT,
        URLSCAN_TAGS_EXCEED_MAX_ERROR,
        URLSCAN_TEST_CONNECTIVITY_ENDPOINT,
    )
    from vault_helpers import add_screenshot_to_vault

logger = getLogger()


def _param_dict(params: Any) -> dict[str, Any]:
    if hasattr(params, "model_dump"):
        return params.model_dump()
    return dict(params)


def replace_null_values(data: Any) -> Any:
    return json.loads(json.dumps(data).replace("\\u0000", "\\\\u0000"))


def _build_action_result(params: Any) -> ActionResult:
    return ActionResult(status=True, message="", param=_param_dict(params))


def _set_result(
    result: ActionResult,
    status: bool,
    message: str,
    *,
    data: dict[str, Any] | None = None,
    summary: dict[str, Any] | None = None,
) -> ActionResult:
    result.set_status(status, message)
    if data is not None:
        result.add_data(replace_null_values(data))
    if summary is not None:
        result.set_summary(summary)
    return result


def _client(asset: BaseAsset) -> UrlscanClient:
    return UrlscanClient(
        api_key=getattr(asset, "api_key", ""),
        timeout=getattr(asset, "timeout", 120.0),
    )


def run_test_connectivity(asset: BaseAsset) -> None:
    client = _client(asset)

    if client.api_key:
        logger.info("Validating API Key")
        response = client.request(
            URLSCAN_TEST_CONNECTIVITY_ENDPOINT,
            headers={"API-Key": client.api_key},
        )
    else:
        logger.info("No API key found, checking connectivity to urlscan.io")
        response = client.request(URLSCAN_TEST_CONNECTIVITY_ENDPOINT)

    if not response.ok:
        raise ActionFailure(response.message)

    logger.info("Test Connectivity Passed")


def run_hunt_domain(params: Any, asset: BaseAsset) -> ActionResult:
    result = _build_action_result(params)
    client = _client(asset)
    response = client.request(
        URLSCAN_HUNT_DOMAIN_ENDPOINT.format(params.domain),
        headers={"API-Key": client.api_key},
    )

    if not response.ok:
        message = (
            response.message
            or (response.data or {}).get("message")
            or URLSCAN_NO_DATA_ERROR
        )
        return _set_result(result, False, message)

    message = (
        URLSCAN_ACTION_SUCCESS
        if response.data.get("results")
        else URLSCAN_NO_DATA_ERROR
    )
    return _set_result(result, True, message, data=response.data)


def run_hunt_ip(params: Any, asset: BaseAsset) -> ActionResult:
    result = _build_action_result(params)
    client = _client(asset)
    response = client.request(
        URLSCAN_HUNT_IP_ENDPOINT.format(params.ip),
        headers={"API-Key": client.api_key},
    )

    if not response.ok:
        message = (
            response.message
            or (response.data or {}).get("message")
            or URLSCAN_NO_DATA_ERROR
        )
        return _set_result(result, False, message)

    message = (
        URLSCAN_ACTION_SUCCESS
        if response.data.get("results")
        else URLSCAN_NO_DATA_ERROR
    )
    return _set_result(result, True, message, data=response.data)


def _poll_submission(
    *,
    report_uuid: str,
    result: ActionResult,
    asset: BaseAsset,
    get_result: bool = True,
    request_context: dict[str, Any] | None = None,
) -> ActionResult:
    client = _client(asset)
    headers = {"Content-Type": "application/json", "API-Key": client.api_key}

    for polling_attempt in range(1, URLSCAN_MAX_POLLING_ATTEMPTS + 1):
        logger.progress(
            f"Polling attempt {polling_attempt} of {URLSCAN_MAX_POLLING_ATTEMPTS}"
        )

        response = client.request(
            URLSCAN_POLL_SUBMISSION_ENDPOINT.format(report_uuid),
            headers=headers,
        )

        if not response.ok:
            if (response.data or {}).get("status", 0) == URLSCAN_BAD_REQUEST_CODE:
                return _set_result(result, False, response.message)
            return _set_result(result, False, response.message or URLSCAN_NO_DATA_ERROR)

        response_data = response.data or {}
        if (
            response_data.get("status", 0) == URLSCAN_NOT_FOUND_CODE
            or response_data.get("message") == "notdone"
        ):
            time.sleep(URLSCAN_POLLING_INTERVAL)
            continue

        if request_context:
            response_data = {**response_data, **request_context}

        if not get_result:
            return _set_result(result, True, URLSCAN_ACTION_SUCCESS)

        tags = response_data.get("task", {}).get("tags", [])
        return _set_result(
            result,
            True,
            URLSCAN_ACTION_SUCCESS,
            data=response_data,
            summary={"added_tags_num": len(tags)},
        )

    return _set_result(result, True, URLSCAN_REPORT_NOT_FOUND_ERROR.format(report_uuid))


def run_get_report(params: Any, asset: BaseAsset) -> ActionResult:
    result = _build_action_result(params)
    return _poll_submission(report_uuid=params.id, result=result, asset=asset)


def _validate_integer(parameter: Any, key: str) -> int:
    try:
        if not float(parameter).is_integer():
            raise ActionFailure(ERROR_INVALID_INT_PARAM.format(key=key))
        value = int(parameter)
    except Exception as exc:
        if isinstance(exc, ActionFailure):
            raise
        raise ActionFailure(ERROR_INVALID_INT_PARAM.format(key=key)) from exc

    if value == 0:
        raise ActionFailure(ERROR_ZERO_INT_PARAM.format(key=key))
    if value < 0:
        raise ActionFailure(ERROR_NEG_INT_PARAM.format(key=key))
    return value


def run_get_screenshot(params: Any, soar: SOARClient, asset: BaseAsset) -> ActionResult:
    result = _build_action_result(params)
    client = _client(asset)
    response = client.request(URLSCAN_SCREENSHOT_ENDPOINT.format(params.report_id))

    if not response.ok or response.response is None:
        return _set_result(result, False, response.message or URLSCAN_NO_DATA_ERROR)

    try:
        container_id = getattr(params, "container_id", None)
        if container_id is None:
            container_id = soar.get_executing_container_id()
        container_id = _validate_integer(container_id, "container_id")

        file_type = response.response.headers.get(
            "Content-Type", "application/octet-stream"
        )
        extension = response.response.url.path.rsplit(".", 1)[-1]
        file_name = f"{params.report_id}.{extension}" if extension else params.report_id

        screenshot_data = add_screenshot_to_vault(
            soar=soar,
            report_id=params.report_id,
            container_id=container_id,
            file_name=file_name,
            response_content=response.response.content,
            file_type=file_type,
        )
    except Exception as exc:
        return _set_result(
            result,
            False,
            f"Failed to download screenshot in Vault. Error : {exc}",
        )

    return _set_result(
        result,
        True,
        f"Screenshot downloaded successfully in container : {container_id}",
        data=screenshot_data,
        summary={
            "vault_id": screenshot_data["vault_id"],
            "name": screenshot_data["name"],
            "file_type": screenshot_data["file_type"],
            "id": screenshot_data["id"],
            "container_id": screenshot_data["container_id"],
            "size": screenshot_data["size"],
        },
    )


def run_detonate_url(params: Any, soar: SOARClient, asset: BaseAsset) -> ActionResult:
    result = _build_action_result(params)
    client = _client(asset)

    if not client.api_key:
        return _set_result(result, False, URLSCAN_API_KEY_MISSING_ERROR)

    tags = [tag.strip() for tag in (params.tags or "").split(",")]
    tags = list(set(filter(None, tags)))
    if len(tags) > URLSCAN_MAX_TAGS_NUM:
        return _set_result(
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
        response_data = response.data or {}
        if response_data.get("status", 0) == URLSCAN_BAD_REQUEST_CODE:
            return _set_result(
                result,
                True,
                URLSCAN_BAD_REQUEST_ERROR.format(
                    response_data.get("message", "None"),
                    response_data.get("description", "None"),
                ),
                data=response_data,
            )
        return _set_result(result, False, response.message or URLSCAN_NO_DATA_ERROR)

    response_data = response.data or {}
    report_uuid = response_data.get("uuid")
    if not report_uuid:
        return _set_result(result, False, URLSCAN_REPORT_UUID_MISSING_ERROR)

    request_context = {
        "requested_url": params.url,
        "requested_get_result": params.get_result,
    }

    if params.get_result or params.addto_vault:
        submission = _poll_submission(
            report_uuid=report_uuid,
            result=result,
            asset=asset,
            get_result=params.get_result,
            request_context=request_context,
        )
        if not submission.get_status():
            return submission

        if params.addto_vault:
            screenshot_params = type(
                "ScreenshotParams",
                (),
                {
                    "report_id": report_uuid,
                    "container_id": getattr(params, "container_id", None),
                    "model_dump": lambda self: {
                        "report_id": report_uuid,
                        "container_id": getattr(params, "container_id", None),
                    },
                },
            )()
            screenshot_result = run_get_screenshot(screenshot_params, soar, asset)
            if not screenshot_result.get_status():
                return screenshot_result

            # The legacy connector re-used the same ActionResult for both polling
            # and vault upload, so the final message reflected the screenshot step.
            submission.set_status(
                screenshot_result.get_status(), screenshot_result.get_message()
            )
            submission.set_summary(
                {
                    **submission.get_summary(),
                    **screenshot_result.get_summary(),
                }
            )

        if params.get_result:
            return submission

    response_data = {**response_data, **request_context}
    return _set_result(result, True, URLSCAN_ACTION_SUCCESS, data=response_data)
