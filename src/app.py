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
from __future__ import annotations

import ipaddress
from pydantic import field_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.params import Param, Params
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.asset import BaseAsset, AssetField

try:
    from .behavior import (
        run_detonate_url,
        run_get_report,
        run_get_screenshot,
        run_hunt_domain,
        run_hunt_ip,
        run_test_connectivity,
    )
    from . import views as views_module
    from .views import (
        render_detonate_url,
        render_get_report,
        render_get_screenshot,
    )
except ImportError:
    from behavior import (
        run_detonate_url,
        run_get_report,
        run_get_screenshot,
        run_hunt_domain,
        run_hunt_ip,
        run_test_connectivity,
    )
    import views as views_module
    from views import render_detonate_url, render_get_report, render_get_screenshot


class Asset(BaseAsset):
    api_key: str | None = AssetField(
        description="API key for urlscan.io", sensitive=True
    )
    timeout: float | None = AssetField(
        description="Timeout period for action (seconds)", default=120.0
    )


class DetonateSummary(ActionOutput):
    added_tags_num: int = OutputField(example_values=[1])
    omitted_tags_num: int | None = OutputField(example_values=[1])
    vault_id: str | None = OutputField(
        example_values=[
            "0599692c5298dd88f731960c55299f8de3331cf1"  # pragma: allowlist secret
        ]
    )
    name: str | None = OutputField(
        example_values=["cf9412df-963e-46a2-849b-de693d055b7b.png"]
    )
    file_type: str | None = OutputField(example_values=["image/png"])
    id: int | None = OutputField(example_values=[722])
    container_id: int | None = OutputField(example_values=[2390])
    size: int | None = OutputField(example_values=[13841])


class ReportSummary(ActionOutput):
    scan_uuid: str | None = OutputField(
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"]
    )
    page_domain: str | None = OutputField(example_values=["yahoo.com"])
    added_tags_num: int = OutputField(example_values=[1])


class LookupSummary(ActionOutput):
    total: int = OutputField(example_values=[1])


class ScreenshotSummary(ActionOutput):
    id: int = OutputField(example_values=[722])
    name: str = OutputField(example_values=["cf9412df-963e-46a2-849b-de693d055b7b.png"])
    size: int = OutputField(example_values=[13841])
    vault_id: str = OutputField(
        example_values=[
            "0599692c5298dd88f731960c55299f8de3331cf1"  # pragma: allowlist secret
        ]
    )
    file_type: str = OutputField(example_values=["image/png"])
    container_id: int = OutputField(example_values=[2390])


class SimplePageOutput(ActionOutput):
    ip: str | None = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    city: str | None = OutputField(example_values=["Bursa"])
    country: str | None = OutputField(example_values=["TR"])
    domain: str | None = OutputField(cef_types=["domain"], example_values=["yahoo.com"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.yahoo.com"]
    )


class SimpleTaskOutput(ActionOutput):
    uuid: str | None = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"],
    )
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.yahoo.com"]
    )
    domain: str | None = OutputField(example_values=["yahoo.com"])


class SimpleStatsOutput(ActionOutput):
    requests: int | None = OutputField(example_values=[69])
    took: int | None = OutputField(example_values=[25])
    total: int | None = OutputField(example_values=[1])


class SearchResultItemOutput(ActionOutput):
    page: SimplePageOutput | None
    task: SimpleTaskOutput | None
    result: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/api/v1/result/86b7f70a-5039-419f-9aeb-8cba09404e92"
        ],
    )
    screenshot: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png"
        ],
    )
    stats: SimpleStatsOutput | None


class LookupActionOutput(ActionOutput):
    has_more: bool | None = OutputField(example_values=[False])
    results: list[SearchResultItemOutput] | None
    took: int | None = OutputField(example_values=[25])
    total: int | None = OutputField(example_values=[1])


class ReportActionOutput(ActionOutput):
    page: SimplePageOutput | None
    task: SimpleTaskOutput | None
    stats: SimpleStatsOutput | None


class DetonateActionOutput(ActionOutput):
    uuid: str | None = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"],
    )
    message: str | None = OutputField(example_values=["Submission successful"])
    description: str | None = OutputField(
        example_values=["The submitted URL was blocked from scanning."]
    )
    status: int | None = OutputField(example_values=[400])
    requested_url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.yahoo.com"]
    )
    requested_get_result: bool | None = OutputField(example_values=[True])
    submitted_tags: list[str] | None = OutputField(
        example_values=[["test_tag1", "test_tag2"]]
    )
    omitted_tags: list[str] | None = OutputField(
        example_values=[["this_tag_is_longer_than_twenty_nine_chars"]]
    )
    omitted_tags_num: int | None = OutputField(example_values=[1])
    page: SimplePageOutput | None
    task: SimpleTaskOutput | None


class ScreenshotActionOutput(ActionOutput):
    report_id: str | None = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"],
    )
    vault_id: str | None = OutputField(
        example_values=[
            "0599692c5298dd88f731960c55299f8de3331cf1"  # pragma: allowlist secret
        ]
    )
    name: str | None = OutputField(
        example_values=["cf9412df-963e-46a2-849b-de693d055b7b.png"]
    )
    file_type: str | None = OutputField(example_values=["image/png"])
    id: int | None = OutputField(example_values=[722])
    container_id: int | None = OutputField(example_values=[2390])
    size: int | None = OutputField(example_values=[13841])


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

views_module.render_get_report = app.view_handler(template="get_report.html")(
    render_get_report
)
views_module.render_detonate_url = app.view_handler(template="detonate_url.html")(
    render_detonate_url
)
views_module.render_get_screenshot = app.view_handler(template="get_screenshot.html")(
    render_get_screenshot
)

get_report_view_handler = views_module.render_get_report
detonate_url_view_handler = views_module.render_detonate_url
get_screenshot_view_handler = views_module.render_get_screenshot


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset):
    """Validate the asset configuration for connectivity using supplied configuration."""
    run_test_connectivity(asset)


class GetReportParams(Params):
    id: str = Param(
        description="Detonation ID for the desired report",
        primary=True,
        cef_types=["urlscan submission id"],
    )


@app.action(
    description="Query for results of an already completed detonation",
    action_type="investigate",
    params_class=GetReportParams,
    output_class=ReportActionOutput,
    summary_type=ReportSummary,
    view_handler=get_report_view_handler,
)
def get_report(params: GetReportParams, soar: SOARClient, asset: Asset):
    return run_get_report(params, asset)


class LookupDomainParams(Params):
    domain: str = Param(
        description="Domain to lookup", primary=True, cef_types=["domain"]
    )


@app.action(
    name="lookup domain",
    identifier="hunt_domain",
    description="Find information about a domain at urlscan.io",
    action_type="investigate",
    params_class=LookupDomainParams,
    output_class=LookupActionOutput,
    summary_type=LookupSummary,
)
def hunt_domain(params: LookupDomainParams, soar: SOARClient, asset: Asset):
    return run_hunt_domain(params, asset)


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


@app.action(
    name="lookup ip",
    identifier="hunt_ip",
    description="Find information about an IP address at urlscan.io",
    action_type="investigate",
    params_class=LookupIpParams,
    output_class=LookupActionOutput,
    summary_type=LookupSummary,
)
def hunt_ip(params: LookupIpParams, soar: SOARClient, asset: Asset):
    return run_hunt_ip(params, asset)


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


@app.action(
    description="Detonate a URL at urlscan.io",
    action_type="investigate",
    read_only=False,
    verbose="If the get_result parameter is set to true, then the action may take up to 2-3 minutes to execute because the action will poll for the results in the same call.",
    params_class=DetonateUrlParams,
    output_class=DetonateActionOutput,
    summary_type=DetonateSummary,
    view_handler=detonate_url_view_handler,
)
def detonate_url(params: DetonateUrlParams, soar: SOARClient, asset: Asset):
    return run_detonate_url(params, soar, asset)


class GetScreenshotParams(Params):
    report_id: str = Param(
        description="UUID of report", primary=True, cef_types=["urlscan submission id"]
    )
    container_id: int | None = Param(
        description="Event to add file to, will default to current container id"
    )


@app.action(
    description="Retrieve copy of screenshot file",
    action_type="generic",
    params_class=GetScreenshotParams,
    output_class=ScreenshotActionOutput,
    summary_type=ScreenshotSummary,
    view_handler=get_screenshot_view_handler,
)
def get_screenshot(params: GetScreenshotParams, soar: SOARClient, asset: Asset):
    return run_get_screenshot(params, soar, asset)


for _name, _obj in list(globals().items()):
    if (
        isinstance(_obj, type)
        and _obj is not ActionOutput
        and issubclass(_obj, ActionOutput)
    ):
        _obj.model_rebuild(_types_namespace=globals(), raise_errors=False)
    if isinstance(_obj, type) and _obj is not Params and issubclass(_obj, Params):
        _obj.model_rebuild(_types_namespace=globals(), raise_errors=False)


if __name__ == "__main__":
    app.cli()
