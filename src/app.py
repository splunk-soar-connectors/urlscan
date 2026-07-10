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
from soar_sdk.app import App
from soar_sdk.asset import BaseAsset, AssetField

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
from .params import (
    DetonateUrlParams,
    GetReportParams,
    GetScreenshotParams,
    LookupDomainParams,
    LookupIpParams,
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
    verify_server_cert: bool | None = AssetField(
        description="Verify server certificate", default=False
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
