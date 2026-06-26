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

from soar_sdk.asset import BaseAsset

from ..client import UrlscanClient


def clean_output_data(data: dict[str, Any]) -> dict[str, Any]:
    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items() if item is not None}
        if isinstance(value, list):
            return [clean(item) for item in value if item is not None]
        return value

    return clean(json.loads(json.dumps(data).replace("\\u0000", "\\\\u0000")))


def make_client(asset: BaseAsset) -> UrlscanClient:
    return UrlscanClient(api_key=asset.api_key, timeout=asset.timeout)
