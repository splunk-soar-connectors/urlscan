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
from soar_sdk.app import App
from soar_sdk.asset import BaseAsset, AssetField
from soar_sdk.params import Param, Params

from .actions.connectivity import run_test_connectivity
from .actions.detonate import run_detonate_url
from .actions.lookup import run_hunt_domain, run_hunt_ip
from .actions.make_request import run_make_request
from .actions.report import run_get_report
from .actions.screenshot import run_get_screenshot
from .outputs import (
    DetonateActionOutput,
    DetonateSummary,
    LookupActionOutput,
    LookupSummary,
    ReportSummary,
    ScreenshotActionOutput,
    ScreenshotSummary,
    UrlscanReportOutput,
)
from .views import (
    render_detonate_url,
    render_get_report,
    render_get_screenshot,
)


class Asset(BaseAsset):
    api_key: str | None = AssetField(
        description="API key for urlscan.io", sensitive=True
    )
    timeout: float | None = AssetField(
        description="Timeout period for action (seconds)", default=120.0
    )


app = App(
    name="urlscan.io",
    app_type="sandbox",
    logo="logo_urlscan.svg",
    logo_dark="logo_urlscan_dark.svg",
    product_vendor="urlscan.io",
    product_name="urlscan.io",
    publisher="Splunk",
    appid="c46c00cd-7231-4dd3-8d8e-02b9fa0e14a2",
    fips_compliant=True,
    asset_cls=Asset,
)


app.test_connectivity()(run_test_connectivity)


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


app.register_action(
    run_get_report,
    identifier="get_report",
    description="Query for results of an already completed detonation",
    action_type="investigate",
    params_class=GetReportParams,
    output_class=UrlscanReportOutput,
    summary_type=ReportSummary,
    view_handler=render_get_report,
    view_template="get_report.html",
)


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


app.register_action(
    run_hunt_domain,
    name="lookup domain",
    identifier="hunt_domain",
    description="Find information about a domain at urlscan.io",
    action_type="investigate",
    params_class=LookupDomainParams,
    output_class=LookupActionOutput,
    summary_type=LookupSummary,
)


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


app.register_action(
    run_hunt_ip,
    name="lookup ip",
    identifier="hunt_ip",
    description="Find information about an IP address at urlscan.io",
    action_type="investigate",
    params_class=LookupIpParams,
    output_class=LookupActionOutput,
    summary_type=LookupSummary,
)


class DetonateUrlParams(Params):
    url: str = Param(
        description="URL to detonate", primary=True, cef_types=["url", "domain"]
    )
    tags: str | None = Param(
        description="Comma-separated list of tags to annotate this scan. Limited to 10 tags. Tags with lengths longer than 29 will be omitted"
    )
    private: bool | None = Param(description="Run a private scan", default=False)
    custom_agent: str | None = Param(description="Override User-Agent for this scan")
    get_result: bool | None = Param(
        description="Get scan result in same call", default=True
    )
    addto_vault: bool | None = Param(
        description="Add url screenshot to vault", default=False
    )


app.register_action(
    run_detonate_url,
    identifier="detonate_url",
    description="Detonate a URL at urlscan.io",
    action_type="investigate",
    read_only=False,
    verbose="If the get_result parameter is set to true, then the action may take up to 2-3 minutes to execute because the action will poll for the results in the same call.",
    params_class=DetonateUrlParams,
    output_class=DetonateActionOutput,
    summary_type=DetonateSummary,
    view_handler=render_detonate_url,
    view_template="detonate_url.html",
)


class GetScreenshotParams(Params):
    report_id: str = Param(
        description="UUID of report", primary=True, cef_types=["urlscan submission id"]
    )
    container_id: int | None = Param(
        description="Event to add file to, will default to current container id"
    )


app.register_action(
    run_get_screenshot,
    identifier="get_screenshot",
    description="Retrieve copy of screenshot file",
    action_type="generic",
    params_class=GetScreenshotParams,
    output_class=ScreenshotActionOutput,
    summary_type=ScreenshotSummary,
    view_handler=render_get_screenshot,
    view_template="get_screenshot.html",
)


app.make_request()(run_make_request)


if __name__ == "__main__":
    app.cli()
