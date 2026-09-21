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
import ipaddress
import uuid

from pydantic import field_validator
from soar_sdk.params import MakeRequestParams, Param, Params


class GetReportParams(Params):
    id: str = Param(
        description="Detonation ID for the desired report",
        primary=True,
        cef_types=["urlscan submission id"],
    )

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        candidate = value.strip()
        try:
            parsed_uuid = uuid.UUID(candidate)
        except (TypeError, ValueError) as exc:
            raise ValueError("Please provide a valid detonation ID") from exc

        if str(parsed_uuid) != candidate.lower():
            raise ValueError("Please provide a valid detonation ID")

        return candidate


class LookupDomainParams(Params):
    domain: str = Param(
        description="Domain to lookup", primary=True, cef_types=["domain"]
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("Please provide a valid domain")

        if len(candidate) > 253:
            raise ValueError("Please provide a valid domain")

        if candidate.lower().startswith(("http://", "https://")):
            raise ValueError("Please provide a valid domain")

        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pass
        else:
            raise ValueError("Please provide a valid domain")

        if not any(char.isalnum() for char in candidate):
            raise ValueError("Please provide a valid domain")

        return candidate


class LookupIpParams(Params):
    ip: str = Param(description="IP to lookup", primary=True, cef_types=["ip", "ipv6"])

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        candidate = value.strip() if isinstance(value, str) else str(value).strip()
        if not candidate:
            raise ValueError("Please provide a valid IPv4 or IPv6 address")

        try:
            ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise ValueError("Please provide a valid IPv4 or IPv6 address") from exc

        return candidate


class DetonateUrlParams(Params):
    url: str = Param(
        description="URL to detonate", primary=True, cef_types=["url", "domain"]
    )
    tags: str | None = Param(
        description="Comma-separated list of tags to annotate this scan. Limited to 10 tags. Tags with lengths longer than 29 will be omitted"
    )
    private: bool = Param(
        description="Run a private scan", default=True, required=False
    )
    custom_agent: str | None = Param(description="Override User-Agent for this scan")
    get_result: bool = Param(
        description="Get scan result in same call", default=True, required=False
    )
    addto_vault: bool = Param(
        description="Add url screenshot to vault", default=False, required=False
    )

    @field_validator("private", "get_result", mode="before")
    @classmethod
    def default_true_for_blank_bool(cls, value: object) -> object:
        return True if value == "" else value

    @field_validator("addto_vault", mode="before")
    @classmethod
    def default_false_for_blank_bool(cls, value: object) -> object:
        return False if value == "" else value


class GetScreenshotParams(Params):
    report_id: str = Param(
        description="UUID of report", primary=True, cef_types=["urlscan submission id"]
    )
    container_id: int | None = Param(
        description="Event to add file to, will default to current container id"
    )

    @field_validator("report_id")
    @classmethod
    def validate_report_id(cls, value: str) -> str:
        candidate = value.strip()
        try:
            parsed_uuid = uuid.UUID(candidate)
        except (TypeError, ValueError) as exc:
            raise ValueError("Please provide a valid report ID") from exc

        if str(parsed_uuid) != candidate.lower():
            raise ValueError("Please provide a valid report ID")

        return candidate


class UrlscanMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "urlscan.io endpoint path, relative to https://urlscan.io. "
            "For example: 'api/v1/search/?q=domain:example.com' or 'api/v1/result/{uuid}'."
        ),
        required=True,
    )
