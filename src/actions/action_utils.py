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

from soar_sdk.action_results import ActionResult
from soar_sdk.asset import BaseAsset

from ..client import UrlscanClient


def build_action_result(params: Any) -> ActionResult:
    param = params.model_dump() if hasattr(params, "model_dump") else dict(params)
    return ActionResult(status=True, message="", param=param)


def set_result(
    result: ActionResult,
    status: bool,
    message: str,
    *,
    data: dict[str, Any] | None = None,
    summary: dict[str, Any] | None = None,
) -> ActionResult:
    result.set_status(status, message)
    if data is not None:
        # SOAR's PostgreSQL backend rejects JSONB payloads containing raw NUL
        # bytes. Round-tripping through JSON escapes literal "\u0000" markers.
        cleaned_data = json.loads(json.dumps(data).replace("\\u0000", "\\\\u0000"))
        result.add_data(cleaned_data)
    if summary is not None:
        result.set_summary(summary)
    return result


def make_client(asset: BaseAsset) -> UrlscanClient:
    return UrlscanClient(api_key=asset.api_key, timeout=asset.timeout)
