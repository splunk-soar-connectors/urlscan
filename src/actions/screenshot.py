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
from soar_sdk.exceptions import ActionFailure, SoarAPIError

from ..client import UrlscanClient
from ..constants import (
    ERROR_INVALID_INT_PARAM,
    ERROR_NEG_INT_PARAM,
    ERROR_ZERO_INT_PARAM,
    URLSCAN_NO_DATA_ERROR,
    URLSCAN_SCREENSHOT_ENDPOINT,
    URLSCAN_SCREENSHOT_SUCCESS_MESSAGE,
)
from ..outputs import ScreenshotActionOutput, ScreenshotSummary
from ..output_utils import clean_output_data


def run_get_screenshot(
    params: Any,
    soar: SOARClient,
    asset: BaseAsset,
    *,
    report_id: str | None = None,
    container_id: int | None = None,
) -> ScreenshotActionOutput:
    report_id = report_id or params.report_id
    if container_id is None:
        container_id = getattr(params, "container_id", None)

    client = UrlscanClient.from_asset(asset)
    response = client.request(URLSCAN_SCREENSHOT_ENDPOINT.format(report_id))

    if not response.ok or response.response is None:
        raise ActionFailure(response.message or URLSCAN_NO_DATA_ERROR)

    if container_id is None:
        container_id = soar.get_executing_container_id()

    try:
        if not float(container_id).is_integer():
            raise ActionFailure(ERROR_INVALID_INT_PARAM.format(key="container_id"))
        container_id = int(container_id)
    except (ValueError, TypeError) as exc:
        raise ActionFailure(ERROR_INVALID_INT_PARAM.format(key="container_id")) from exc

    if container_id == 0:
        raise ActionFailure(ERROR_ZERO_INT_PARAM.format(key="container_id"))
    if container_id < 0:
        raise ActionFailure(ERROR_NEG_INT_PARAM.format(key="container_id"))

    file_type = response.response.headers.get(
        "Content-Type", "application/octet-stream"
    )
    extension = response.response.url.path.rsplit(".", 1)[-1]
    file_name = f"{report_id}.{extension}" if extension else report_id

    try:
        vault_id = soar.vault.create_attachment(
            container_id=container_id,
            file_content=response.response.content,
            file_name=file_name,
        )
        attachments = soar.vault.get_attachment(
            vault_id=vault_id, container_id=container_id
        )
        if not attachments:
            raise SoarAPIError(
                "Could not find meta information of the downloaded screenshot's Vault"
            )
    except SoarAPIError as exc:
        raise ActionFailure(
            f"Failed to download screenshot in Vault. Error : {exc}"
        ) from exc

    attachment = attachments[0]
    screenshot_data = {
        "report_id": report_id,
        "vault_id": attachment.vault_id,
        "name": attachment.name,
        "file_type": file_type,
        "id": attachment.id,
        "container_id": attachment.container_id,
        "size": attachment.size,
    }

    soar.set_message(
        URLSCAN_SCREENSHOT_SUCCESS_MESSAGE.format(container_id=container_id)
    )
    soar.set_summary(
        ScreenshotSummary(
            vault_id=screenshot_data["vault_id"],
            name=screenshot_data["name"],
            file_type=screenshot_data["file_type"],
            id=screenshot_data["id"],
            container_id=screenshot_data["container_id"],
            size=screenshot_data["size"],
        )
    )
    return ScreenshotActionOutput(**clean_output_data(screenshot_data))
