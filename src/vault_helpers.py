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
from soar_sdk.exceptions import SoarAPIError


def add_screenshot_to_vault(
    *,
    soar: SOARClient,
    report_id: str,
    container_id: int,
    file_name: str,
    response_content: bytes,
    file_type: str,
) -> dict[str, Any]:
    vault_id = soar.vault.create_attachment(
        container_id=container_id,
        file_content=response_content,
        file_name=file_name,
    )

    attachments = soar.vault.get_attachment(
        vault_id=vault_id, container_id=container_id
    )
    if not attachments:
        raise SoarAPIError(
            "Could not find meta information of the downloaded screenshot's Vault"
        )

    attachment = attachments[0]
    return {
        "report_id": report_id,
        "vault_id": attachment.vault_id,
        "name": attachment.name,
        "file_type": file_type,
        "id": attachment.id,
        "container_id": attachment.container_id,
        "size": attachment.size,
        "path": attachment.path,
    }
