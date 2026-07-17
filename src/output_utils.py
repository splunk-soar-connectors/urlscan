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


_REDACTION_MARKER = "[REDACTED]"
_HEADER_CONTAINER_KEYS = {"headers", "requestheaders"}
_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
}


def _redact_captured_secrets(value: Any, parent_key: str | None = None) -> Any:
    if isinstance(value, list):
        return [_redact_captured_secrets(item, parent_key) for item in value]

    if not isinstance(value, dict):
        return value

    redacted: dict[Any, Any] = {}
    for key, item in value.items():
        normalized_key = str(key).lower()
        if (parent_key == "cookies" and normalized_key == "value") or (
            parent_key in _HEADER_CONTAINER_KEYS
            and normalized_key in _SENSITIVE_HEADER_KEYS
        ):
            redacted[key] = _REDACTION_MARKER
        else:
            redacted[key] = _redact_captured_secrets(item, normalized_key)

    return redacted


def clean_output_data(data: dict[str, Any]) -> dict[str, Any]:
    cleaned = json.loads(json.dumps(data).replace("\\u0000", "\\\\u0000"))
    return _redact_captured_secrets(cleaned)
