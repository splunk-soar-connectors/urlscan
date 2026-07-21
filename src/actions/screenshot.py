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
import tempfile
from pathlib import Path
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.asset import BaseAsset
from soar_sdk.exceptions import ActionFailure, SoarAPIError

from ..client import UrlscanClient
from ..constants import (
    ERROR_INVALID_INT_PARAM,
    ERROR_NEG_INT_PARAM,
    ERROR_ZERO_INT_PARAM,
    URLSCAN_DEFAULT_MAX_SCREENSHOT_SIZE_MB,
    URLSCAN_INVALID_SCREENSHOT_SIZE_ERROR,
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

    max_size_mb = getattr(
        asset, "max_screenshot_size_mb", URLSCAN_DEFAULT_MAX_SCREENSHOT_SIZE_MB
    )
    if (
        not isinstance(max_size_mb, int)
        or isinstance(max_size_mb, bool)
        or max_size_mb <= 0
    ):
        raise ActionFailure(URLSCAN_INVALID_SCREENSHOT_SIZE_ERROR)
    max_size_bytes = max_size_mb * 1024 * 1024

    temporary_file: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=soar.vault.get_vault_tmp_dir(), delete=False
        ) as destination:
            temporary_file = Path(destination.name)
            client = UrlscanClient.from_asset(asset)
            file_type, response_path = client.download_screenshot(
                URLSCAN_SCREENSHOT_ENDPOINT.format(report_id),
                destination,
                max_size_bytes,
            )

        extension = response_path.rsplit(".", 1)[-1]
        file_name = f"{report_id}.{extension}" if extension else report_id
        vault_id = soar.vault.add_attachment(
            container_id=container_id,
            file_location=str(temporary_file),
            file_name=file_name,
        )
        attachments = soar.vault.get_attachment(
            vault_id=vault_id, container_id=container_id
        )
        if not attachments:
            raise SoarAPIError(
                "Could not find meta information of the downloaded screenshot's Vault"
            )
    except (OSError, SoarAPIError) as exc:
        raise ActionFailure(
            f"Failed to download screenshot in Vault. Error : {exc}"
        ) from exc
    finally:
        if temporary_file is not None:
            temporary_file.unlink(missing_ok=True)

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
