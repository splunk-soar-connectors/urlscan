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
from soar_sdk.logging import getLogger

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

logger = getLogger()


class Asset(BaseAsset):
    api_key: str | None = AssetField(description="API key for urlscan.io")
    timeout: float | None = AssetField(
        description="Timeout period for action (seconds)", default=120.0
    )


class AddedTagsSummary(ActionOutput):
    added_tags_num: float = OutputField(example_values=[1])


class ScreenshotSummary(ActionOutput):
    id: float = OutputField(example_values=[722])
    name: str = OutputField(example_values=["cf9412df-963e-46a2-849b-de693d055b7b.png"])
    size: float = OutputField(example_values=[13841])
    vault_id: str = OutputField(
        example_values=[
            "0599692c5298dd88f731960c55299f8de3331cf1"  # pragma: allowlist secret
        ]
    )
    file_type: str = OutputField(example_values=["image/png"])
    container_id: float = OutputField(example_values=[2390])


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
    requests: float | None = OutputField(example_values=[69])
    took: float | None = OutputField(example_values=[25])
    total: float | None = OutputField(example_values=[1])


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
    took: float | None = OutputField(example_values=[25])
    total: float | None = OutputField(example_values=[1])


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
    status: float | None = OutputField(example_values=[400])
    requested_url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.yahoo.com"]
    )
    requested_get_result: bool | None
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
    id: float | None = OutputField(example_values=[722])
    container_id: float | None = OutputField(example_values=[2390])
    size: float | None = OutputField(example_values=[13841])


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
    run_test_connectivity(asset)


class GetReportParams(Params):
    id: str = Param(
        description="Detonation ID for the desired report",
        primary=True,
        cef_types=["urlscan submission id"],
    )


class MessageOutput(ActionOutput):
    column: float = OutputField(example_values=[552])
    level: str = OutputField(example_values=["log"])
    line: float = OutputField(example_values=[2])
    source: str = OutputField(example_values=["console-api"])
    text: str = OutputField(
        example_values=["JQMIGRATE: Migrate is installed, version 1.4.1"]
    )
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class ConsoleOutput(ActionOutput):
    message: MessageOutput


class CookiesOutput(ActionOutput):
    domain: str = OutputField(cef_types=["domain"], example_values=[".test.test"])
    expires: float = OutputField(example_values=[1620630019.555948])
    httpOnly: bool = OutputField(example_values=[False])
    name: str = OutputField(example_values=["TestName"])
    path: str = OutputField(example_values=["/"])
    priority: str = OutputField(example_values=["Medium"])
    sameParty: bool = OutputField(example_values=[False])
    sameSite: str
    secure: bool = OutputField(example_values=[True])
    session: bool = OutputField(example_values=[False])
    size: float = OutputField(example_values=[12])
    sourcePort: float = OutputField(example_values=[443])
    sourceScheme: str = OutputField(example_values=["Secure"])
    value: str = OutputField(example_values=["ARxQvcfS"])


class GlobalsOutput(ActionOutput):
    prop: str = OutputField(example_values=["onbeforexrselect"])
    type: str = OutputField(example_values=["object"])


class LinksOutput(ActionOutput):
    href: str = OutputField(cef_types=["url"], example_values=["https://test.test"])
    text: str = OutputField(example_values=["Feedback"])


class InitiatorinfoOutput(ActionOutput):
    host: str = OutputField(example_values=["test.test"])
    type: str = OutputField(example_values=["parser"])
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class CallframesOutput(ActionOutput):
    columnNumber: float = OutputField(example_values=[16])
    functionName: str
    lineNumber: float = OutputField(example_values=[26])
    scriptId: str = OutputField(example_values=["31"])
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class StackOutput(ActionOutput):
    callFrames: list[CallframesOutput]


class InitiatorOutput(ActionOutput):
    type: str = OutputField(example_values=["other"])


class HeadersOutput(ActionOutput):
    Accept_Ranges: str = OutputField(example_values=["bytes"], alias="Accept-Ranges")
    Access_Control_Allow_Credentials: str = OutputField(
        example_values=["true"], alias="Access-Control-Allow-Credentials"
    )
    Access_Control_Allow_Headers: str = OutputField(
        example_values=["origin,range,hdntl,hdnts"],
        alias="Access-Control-Allow-Headers",
    )
    Access_Control_Allow_Methods: str = OutputField(
        example_values=["GET,POST,OPTIONS"], alias="Access-Control-Allow-Methods"
    )
    Access_Control_Allow_Origin: str = OutputField(
        example_values=["*"], alias="Access-Control-Allow-Origin"
    )
    Access_Control_Expose_Headers: str = OutputField(
        example_values=["Content-Range, X-ATLAS-MARKERS"],
        alias="Access-Control-Expose-Headers",
    )
    Access_Control_Max_Age: str = OutputField(
        example_values=["86400"], alias="Access-Control-Max-Age"
    )
    Age: str = OutputField(example_values=["0"])
    Alt_Svc: str = OutputField(
        example_values=[
            'h3-29=":443"; ma=93600,h3-Q050=":443"; ma=93600,quic=":443"; ma=93600; v="46,43"'
        ],
        alias="Alt-Svc",
    )
    Cache_Control: str = OutputField(
        example_values=["no-cache, no-store, must-revalidate"], alias="Cache-Control"
    )
    Connection: str = OutputField(example_values=["Upgrade, Keep-Alive"])
    Content_Encoding: str = OutputField(
        example_values=["gzip"], alias="Content-Encoding"
    )
    Content_Length: str = OutputField(example_values=["25663"], alias="Content-Length")
    Content_Security_Policy_Report_Only: str = OutputField(
        example_values=[
            "default-src 'none'; block-all-mixed-content; connect-src https://*.abc.test.test https://*.abc.abc.test 'self'; frame-ancestors 'none'; img-src 'self' https://test.img https://*.img.test; media-src 'none'; script-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q'; style-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q';"
        ],
        alias="Content-Security-Policy-Report-Only",
    )
    Content_Type: str = OutputField(example_values=["image/png"], alias="Content-Type")
    Date: str = OutputField(example_values=["Tue, 08 Aug 2017 15:04:49 GMT"])
    ETag: str = OutputField(example_values=['"52613b8-643f-5449ffc1d1aee"'])
    Etag: str = OutputField(example_values=['"test1705564909da7f9eaf749dbbfbb1"'])
    Expect_CT: str = OutputField(
        example_values=[
            'max-age=31536000, report-uri="http://abc.test.test/beacon/csp?src=test-expect-ct-report-only"'
        ],
        alias="Expect-CT",
    )
    Expires: str = OutputField(example_values=["0"])
    Keep_Alive: str = OutputField(
        example_values=["timeout=5, max=300"], alias="Keep-Alive"
    )
    Last_Modified: str = OutputField(
        example_values=["Tue, 27 Dec 2016 08:53:23 GMT"], alias="Last-Modified"
    )
    Pragma: str = OutputField(example_values=["no-cache"])
    Public_Key_Pins_Report_Only: str = OutputField(alias="Public-Key-Pins-Report-Only")
    Referrer_Policy: str = OutputField(
        example_values=["strict-origin-when-cross-origin"], alias="Referrer-Policy"
    )
    Server: str = OutputField(example_values=["TestServer/1.4"])
    Strict_Transport_Security: str = OutputField(
        example_values=["max-age=31536000; includeSubDomains"],
        alias="Strict-Transport-Security",
    )
    Timing_Allow_Origin: str = OutputField(
        example_values=["*"], alias="Timing-Allow-Origin"
    )
    Upgrade: str = OutputField(example_values=["h2,h2c"])
    Via: str = OutputField(
        example_values=["1.1 19e8b9893b635d62599a448aea7db.test.test"]
    )
    X_Amz_Cf_Id: str = OutputField(
        example_values=[
            "W1YaaqDYWLSgU38zsXQ7Xt55F4FdEAEdd0YNqtTtvs3DkqA=="  # pragma: allowlist secret
        ],
        alias="X-Amz-Cf-Id",
    )
    X_Amz_Cf_Pop: str = OutputField(example_values=["VIE50-C1"], alias="X-Amz-Cf-Pop")
    X_Cache: str = OutputField(example_values=["HIT"], alias="X-Cache")
    X_Content_Type_Options: str = OutputField(
        example_values=["nosniff"], alias="X-Content-Type-Options"
    )
    X_Frame_Options: str = OutputField(example_values=["DENY"], alias="X-Frame-Options")
    X_LLID: str = OutputField(
        cef_types=["md5"],
        example_values=["40b5a42c1598c14b83edff465cd62db1"],  # pragma: allowlist secret
        alias="X-LLID",
    )
    X_Powered_By: str = OutputField(example_values=["Express"], alias="X-Powered-By")
    X_XSS_Protection: str = OutputField(
        example_values=["1; mode=block"], alias="X-XSS-Protection"
    )
    accept_ranges: str = OutputField(example_values=["bytes"], alias="accept-ranges")
    access_control_allow_methods: str = OutputField(
        example_values=["GET"], alias="access-control-allow-methods"
    )
    access_control_allow_origin: str = OutputField(
        example_values=["*"], alias="access-control-allow-origin"
    )
    age: str = OutputField(example_values=["520785"])
    alt_svc: str = OutputField(
        example_values=['quic=":443"; ma=2592000; v="39,38,37,36,35"'], alias="alt-svc"
    )
    ats_carp_promotion: str = OutputField(
        example_values=["1"], alias="ats-carp-promotion"
    )
    cache_control: str = OutputField(
        example_values=["no-cache, must-revalidate, max-age=0"], alias="cache-control"
    )
    content_encoding: str = OutputField(
        example_values=["gzip"], alias="content-encoding"
    )
    content_length: str = OutputField(example_values=["29453"], alias="content-length")
    content_security_policy_report_only: str = OutputField(
        example_values=[
            "default-src 'self'; report-uri https://abc.test.test/beacon/csp?src=test"
        ],
        alias="content-security-policy-report-only",
    )
    content_type: str = OutputField(
        example_values=["text/html; charset=UTF-8"], alias="content-type"
    )
    date: str = OutputField(example_values=["Tue, 08 Aug 2017 15:04:47 GMT"])
    etag: str = OutputField(example_values=['"5267f53-62c-53514e7323a80"'])
    expect_ct: str = OutputField(
        example_values=[
            'max-age=31536000, report-uri="http://abc.test.test/beacon/csp?src=test-expect-ct-report-only"'
        ],
        alias="expect-ct",
    )
    expires: str = OutputField(example_values=["Wed, 11 Jan 1984 05:00:00 GMT"])
    last_modified: str = OutputField(
        example_values=["Sun, 12 Jun 2016 13:39:38 GMT"], alias="last-modified"
    )
    link: str = OutputField(
        example_values=['<https://test.test/>; rel="https://api.test.test/"']
    )
    referrer_policy: str = OutputField(
        example_values=["no-referrer-when-downgrade"], alias="referrer-policy"
    )
    server: str = OutputField(example_values=["TestServer/1.4"])
    status: str = OutputField(example_values=["200"])
    strict_transport_security: str = OutputField(
        example_values=["max-age=15552000"], alias="strict-transport-security"
    )
    timing_allow_origin: str = OutputField(
        example_values=["*"], alias="timing-allow-origin"
    )
    vary: str = OutputField(example_values=["Accept-Encoding"])
    via: str = OutputField(
        example_values=["1.1 e8b17f734954ee4d46d2f302323482.test.test"]
    )
    x_amz_cf_id: str = OutputField(
        example_values=[
            "Ob7ZSkPXvNH-2XbYyQH7lZFv5GbTNPkCXbSwtcOodIA=="  # pragma: allowlist secret
        ],
        alias="x-amz-cf-id",
    )
    x_amz_cf_pop: str = OutputField(example_values=["FRA53-C1"], alias="x-amz-cf-pop")
    x_amz_id_2: str = OutputField(
        example_values=[
            "ha+gqKNXBkV1gqr4AHswgx1OZSCdM7otKBZCL/JFLsojoWZn3JWVruarvQAhNV9ejI7FMh7PalI="  # pragma: allowlist secret
        ],
        alias="x-amz-id-2",
    )
    x_amz_request_id: str = OutputField(
        example_values=["2KMY2R40Y5WJNG70"], alias="x-amz-request-id"
    )
    x_amz_server_side_encryption: str = OutputField(
        example_values=["AES256"], alias="x-amz-server-side-encryption"
    )
    x_cache: str = OutputField(example_values=["Hit from TestCloud"], alias="x-cache")
    x_content_type_options: str = OutputField(
        example_values=["nosniff"], alias="x-content-type-options"
    )
    x_frame_options: str = OutputField(
        example_values=["SAMEORIGIN"], alias="x-frame-options"
    )
    x_xss_protection: str = OutputField(
        example_values=["1; mode=block"], alias="x-xss-protection"
    )


class RequestheadersOutput(ActionOutput):
    Accept: str = OutputField(
        example_values=[
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
        ]
    )
    Accept_Encoding: str = OutputField(
        example_values=["gzip, deflate, br"], alias="Accept-Encoding"
    )
    Accept_Language: str = OutputField(
        example_values=["en-US"], alias="Accept-Language"
    )
    Cache_Control: str = OutputField(example_values=["no-cache"], alias="Cache-Control")
    Connection: str = OutputField(example_values=["keep-alive"])
    Cookie: str = OutputField(
        example_values=["B=5m9tgmtg9hknr&b=3&s=6v; GUCS=ARxQvcfS"]
    )
    Host: str = OutputField(example_values=["abc.test.test"])
    Pragma: str = OutputField(example_values=["no-cache"])
    Sec_Fetch_Dest: str = OutputField(
        example_values=["document"], alias="Sec-Fetch-Dest"
    )
    Sec_Fetch_Mode: str = OutputField(
        example_values=["navigate"], alias="Sec-Fetch-Mode"
    )
    Sec_Fetch_Site: str = OutputField(alias="Sec-Fetch-Site")
    Sec_Fetch_User: str = OutputField(example_values=["?1"], alias="Sec-Fetch-User")
    Upgrade_Insecure_Requests: str = OutputField(
        example_values=["1"], alias="Upgrade-Insecure-Requests"
    )
    User_Agent: str = OutputField(
        example_values=["TestBrowser/7.0"], alias="User-Agent"
    )


class SecuritydetailsOutput(ActionOutput):
    certificateId: float = OutputField(example_values=[0])
    certificateTransparencyCompliance: str = OutputField(example_values=["unknown"])
    cipher: str = OutputField(example_values=["AES_128_GCM"])
    issuer: str = OutputField(example_values=["Test Authority"])
    keyExchange: str = OutputField(example_values=["ECDHE_RSA"])
    keyExchangeGroup: str = OutputField(example_values=["P-256"])
    protocol: str = OutputField(example_values=["TLS 1.2"])
    sanList: str = OutputField(example_values=["www.test.test"])
    signedCertificateTimestampList: list[SignedcertificatetimestamplistOutput]
    subjectName: str = OutputField(example_values=["test.test"])
    validFrom: float = OutputField(example_values=[1498179660])
    validTo: float = OutputField(example_values=[1505955660])


class TimingOutput(ActionOutput):
    beginNavigation: str = OutputField(example_values=["2017-08-08T15:04:49.619Z"])
    domContentEventFired: str = OutputField(example_values=["2017-08-08T15:04:50.903Z"])
    frameNavigated: str = OutputField(example_values=["2017-08-08T15:04:51.396Z"])
    frameStartedLoading: str = OutputField(example_values=["2017-08-08T15:04:50.903Z"])
    frameStoppedLoading: str = OutputField(example_values=["2017-08-08T15:04:52.370Z"])
    loadEventFired: str = OutputField(example_values=["2017-08-08T15:04:52.370Z"])


class RedirectresponseOutput(ActionOutput):
    asn: AsnOutput
    encodedDataLength: float = OutputField(example_values=[1132])
    fromPrefetchCache: bool = OutputField(example_values=[False])
    geoip: GeoipOutput
    headers: HeadersOutput
    mimeType: str = OutputField(example_values=["text/html"])
    protocol: str = OutputField(cef_types=["url"], example_values=["http/1.1"])
    rdns: RdnsOutput
    remoteIPAddress: str = OutputField(
        cef_types=["ip", "ipv6"], example_values=["[2a00:1288:110:c305::1:8000]"]
    )
    remotePort: float = OutputField(example_values=[80])
    requestHeaders: RequestheadersOutput
    responseTime: float = OutputField(example_values=[1620628219395.843])
    securityDetails: SecuritydetailsOutput
    securityState: str = OutputField(example_values=["insecure"])
    status: float = OutputField(example_values=[301])
    statusText: str = OutputField(example_values=["Moved Permanently"])
    timing: TimingOutput
    url: str = OutputField(cef_types=["url"], example_values=["http://abc.test.test/"])


class PostdataentriesOutput(ActionOutput):
    bytes: str


class RequestOutput(ActionOutput):
    headers: HeadersOutput
    initialPriority: str = OutputField(example_values=["VeryHigh"])
    method: str = OutputField(example_values=["GET"])
    mixedContentType: str
    referrerPolicy: str = OutputField(
        example_values=["strict-origin-when-cross-origin"]
    )
    url: str = OutputField(cef_types=["url"], example_values=["http://abc.test.test/"])


class AsnOutput(ActionOutput):
    asn: str = OutputField(example_values=["15169"])
    country: str = OutputField(example_values=["US"])
    date: str = OutputField(example_values=["2000-03-30"])
    description: str = OutputField(example_values=["TEST - Test Inc., US"])
    ip: str = OutputField(example_values=["2a00:1450:4001:814::200a"])
    name: str = OutputField(example_values=["Test Inc."])
    registrar: str = OutputField(example_values=["arin"])
    route: str = OutputField(example_values=["2a00:1288:110::/48"])


class GeoipOutput(ActionOutput):
    area: float = OutputField(example_values=[100])
    city: str
    country: str = OutputField(example_values=["BG"])
    country_name: str = OutputField(example_values=["Bulgaria"])
    eu: str = OutputField(example_values=["0"])
    ll: float = OutputField(example_values=[-8])
    metro: float = OutputField(example_values=[0])
    range: float = OutputField(example_values=[1475903487])
    region: str
    timezone: str = OutputField(example_values=["Europe/London"])
    zip: float = OutputField(example_values=[0])


class RdnsOutput(ActionOutput):
    ip: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    ptr: str = OutputField(example_values=["abc.test.test"])


class RequestsOutput(ActionOutput):
    initiatorInfo: InitiatorinfoOutput
    request: RequestOutput
    requests: list[RequestsOutput]
    response: ResponseOutput


class AbpOutput(ActionOutput):
    data: list[DataOutput]
    state: str = OutputField(example_values=["done"])


class FailedOutput(ActionOutput):
    blockedReason: str = OutputField(example_values=["mixed-content"])
    canceled: bool
    errorText: str
    requestId: str = OutputField(example_values=["8956.7"])
    timestamp: float = OutputField(example_values=[25133388.092608])
    type: str = OutputField(example_values=["Stylesheet"])


class HashmatchesOutput(ActionOutput):
    file: str = OutputField(
        example_values=["jquery-migrate/1.4.1/jquery-migrate.min.js"]
    )
    project: str = OutputField(example_values=["jquery-migrate"])
    project_url: str = OutputField(
        cef_types=["url"], example_values=["https://test.test"]
    )
    source: str = OutputField(example_values=["Test Inc."])
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class SignedcertificatetimestamplistOutput(ActionOutput):
    hashAlgorithm: str = OutputField(example_values=["SHA-256"])
    logDescription: str = OutputField(example_values=["Test 'test' log"])
    logId: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "EE4BBDB775CE60BAE142691FABE19E66A30F7E5FB072D88300C47B897AA8FDCB"  # pragma: allowlist secret
        ],
    )
    origin: str = OutputField(example_values=["TLS extension"])
    signatureAlgorithm: str = OutputField(example_values=["ECDSA"])
    signatureData: str = OutputField(
        example_values=[
            "3045022100AB7CB0ADFD0A97125FCAFD75E16A0D7A963F97320318AFA76DFDDC760E67B0C602203C006DC6534D6C297F5B65897285E04AE6C303A5C3C6D7E7FAEF75A33E95CB23"  # pragma: allowlist secret
        ]
    )
    status: str = OutputField(example_values=["Verified"])
    timestamp: float = OutputField(example_values=[1500976717935])


class SecurityheadersOutput(ActionOutput):
    name: str = OutputField(example_values=["X-Content-Type-Options"])
    value: str = OutputField(example_values=["nosniff"])


class ResponseOutput(ActionOutput):
    abp: AbpOutput
    asn: AsnOutput
    dataLength: float = OutputField(example_values=[29453])
    encodedDataLength: float = OutputField(example_values=[29660])
    failed: FailedOutput
    geoip: GeoipOutput
    hash: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "824c215e931c70313b86d89c6ddb4c4c3b0a29604dc3a4f3ef287364e8d80607"  # pragma: allowlist secret
        ],
    )
    hashmatches: list[HashmatchesOutput]
    rdns: RdnsOutput
    requestId: str = OutputField(example_values=["8956.1"])
    response: ResponseOutput
    size: float = OutputField(example_values=[29453])
    type: str = OutputField(example_values=["Document"])


class DataOutput(ActionOutput):
    ip: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    ptr: str = OutputField(example_values=["abc.test.test"])


class CertificatesOutput(ActionOutput):
    issuer: str = OutputField(example_values=["Test Authority"])
    sanList: str = OutputField(example_values=["test.test"])
    subjectName: str = OutputField(example_values=["test.test"])
    validFrom: float = OutputField(example_values=[1498179660])
    validTo: float = OutputField(example_values=[1505955660])


class ListsOutput(ActionOutput):
    asns: str = OutputField(example_values=["15169"])
    certificates: list[CertificatesOutput]
    countries: str = OutputField(example_values=["IE"])
    domains: str = OutputField(example_values=["abc.test.test"])
    hashes: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "581812adb789400372e69ee2a4aa7d58cdd009718a3faa114dd30dcc196fdeb8"  # pragma: allowlist secret
        ],
    )
    ips: str = OutputField(example_values=["2a00:1450:4001:824::2003"])
    linkDomains: str = OutputField(example_values=["test.test"])
    servers: str = OutputField(example_values=["ESF"])
    urls: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class CdnjsOutput(ActionOutput):
    data: list[DataOutput]
    state: str = OutputField(example_values=["done"])


class DoneOutput(ActionOutput):
    data: DataOutput
    state: str = OutputField(example_values=["done"])


class ThreatOutput(ActionOutput):
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class MatchesOutput(ActionOutput):
    cacheDuration: str = OutputField(example_values=["300s"])
    platformType: str = OutputField(example_values=["ANY_PLATFORM"])
    threat: ThreatOutput
    threatEntryType: str = OutputField(example_values=["URL"])
    threatType: str = OutputField(example_values=["SOCIAL_ENGINEERING"])


class GsbOutput(ActionOutput):
    data: DataOutput
    state: str = OutputField(example_values=["done"])


class WappaOutput(ActionOutput):
    state: str = OutputField(example_values=["done"])


class ProcessorsOutput(ActionOutput):
    abp: AbpOutput
    asn: AsnOutput
    cdnjs: CdnjsOutput
    done: DoneOutput
    geoip: GeoipOutput
    gsb: GsbOutput
    rdns: RdnsOutput
    wappa: WappaOutput


class MetaOutput(ActionOutput):
    processors: ProcessorsOutput


class PageOutput(ActionOutput):
    asn: str = OutputField(example_values=["AS"])
    asnname: str
    city: str
    country: str = OutputField(example_values=["BG"])
    domain: str = OutputField(cef_types=["domain"], example_values=["test.test"])
    ip: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    ptr: str = OutputField(example_values=["abc.test.test"])
    server: str = OutputField(example_values=["TestServer/1.4"])
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class DomainstatsOutput(ActionOutput):
    count: float = OutputField(example_values=[54])
    countries: str = OutputField(example_values=["IE"])
    domain: str = OutputField(cef_types=["domain"], example_values=["test.test"])
    encodedSize: float = OutputField(example_values=[894416])
    index: float = OutputField(example_values=[0])
    initiators: str = OutputField(example_values=["test.test"])
    ips: str = OutputField(example_values=["[2a00:1450:4001:814::200a]"])
    redirects: float = OutputField(example_values=[0])
    size: float = OutputField(example_values=[889425])


class IpstatsOutput(ActionOutput):
    asn: AsnOutput
    count: str
    countries: str = OutputField(example_values=["IE"])
    domains: str = OutputField(example_values=["abc.test.test"])
    encodedSize: float = OutputField(example_values=[894416])
    geoip: GeoipOutput
    index: float = OutputField(example_values=[0])
    ip: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    ipv6: bool
    rdns: RdnsOutput
    redirects: float = OutputField(example_values=[3])
    requests: float = OutputField(example_values=[54])
    size: float = OutputField(example_values=[889425])


class ProtocolstatsOutput(ActionOutput):
    count: float = OutputField(example_values=[59])
    countries: str = OutputField(example_values=["BG"])
    encodedSize: float = OutputField(example_values=[976819])
    ips: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    protocol: str = OutputField(cef_types=["url"], example_values=["spdy"])
    size: float = OutputField(example_values=[1056847])


class SubdomainsOutput(ActionOutput):
    country: str = OutputField(example_values=["GB"])
    domain: str = OutputField(cef_types=["domain"], example_values=["maps"])
    failed: bool


class RegdomainstatsOutput(ActionOutput):
    count: float = OutputField(example_values=[54])
    encodedSize: float = OutputField(example_values=[894416])
    index: float = OutputField(example_values=[0])
    ips: str = OutputField(example_values=["[2a00:1450:4001:814::200a]"])
    redirects: float = OutputField(example_values=[4])
    regDomain: str = OutputField(cef_types=["domain"], example_values=["test.test"])
    size: float = OutputField(example_values=[889425])
    subDomains: list[SubdomainsOutput]


class ResourcestatsOutput(ActionOutput):
    compression: str = OutputField(example_values=["1.0"])
    count: float = OutputField(example_values=[21])
    countries: str = OutputField(example_values=["BG"])
    encodedSize: float = OutputField(example_values=[361619])
    ips: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    latency: float = OutputField(example_values=[0])
    percentage: float = OutputField(example_values=[30])
    size: float = OutputField(example_values=[366814])
    type: str = OutputField(example_values=["Script"])


class ServerstatsOutput(ActionOutput):
    count: float = OutputField(example_values=[54])
    countries: str = OutputField(example_values=["IE"])
    encodedSize: float = OutputField(example_values=[894416])
    ips: str = OutputField(example_values=["[2a00:1450:4001:824::200a]"])
    server: str = OutputField(example_values=["TestServer/1.4"])
    size: float = OutputField(example_values=[889425])


class Tls1Output(ActionOutput):
    n2___ECDHE_ECDSA___AES_128_GCM: float = OutputField(
        example_values=[4], alias="2 / ECDHE_ECDSA / AES_128_GCM"
    )
    n2___ECDHE_RSA___AES_128_GCM: float = OutputField(
        example_values=[55], alias="2 / ECDHE_RSA / AES_128_GCM"
    )
    n3______AES_128_GCM: float = OutputField(
        example_values=[17], alias="3 /  / AES_128_GCM"
    )
    n3______AES_256_GCM: float = OutputField(
        example_values=[3], alias="3 /  / AES_256_GCM"
    )


class ProtocolsOutput(ActionOutput):
    TLS_1: Tls1Output


class TlsstatsOutput(ActionOutput):
    count: float = OutputField(example_values=[59])
    countries: str = OutputField(example_values=["BG"])
    encodedSize: float = OutputField(example_values=[976819])
    ips: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    protocols: ProtocolsOutput
    securityState: str = OutputField(example_values=["secure"])
    size: float = OutputField(example_values=[1056847])


class StatsOutput(ActionOutput):
    IPv6Percentage: float = OutputField(example_values=[75])
    adBlocked: float = OutputField(example_values=[2])
    domainStats: list[DomainstatsOutput]
    ipStats: list[IpstatsOutput]
    malicious: float = OutputField(example_values=[51])
    protocolStats: list[ProtocolstatsOutput]
    regDomainStats: list[RegdomainstatsOutput]
    resourceStats: list[ResourcestatsOutput]
    securePercentage: float = OutputField(example_values=[86])
    secureRequests: float = OutputField(example_values=[59])
    serverStats: list[ServerstatsOutput]
    tlsStats: list[TlsstatsOutput]
    totalLinks: float = OutputField(example_values=[4])
    uniqCountries: float = OutputField(example_values=[2])


class SubmitterOutput(ActionOutput):
    country: str = OutputField(example_values=["US"])


class OptionsOutput(ActionOutput):
    useragent: str = OutputField(example_values=["TestBrowser/7.0"])


class TaskOutput(ActionOutput):
    domURL: str = OutputField(
        cef_types=["url"],
        example_values=["https://urlscan.io/dom/86b7f70a-5039-419f-9aeb-8cba09404e92/"],
    )
    method: str = OutputField(example_values=["manual"])
    options: OptionsOutput
    reportURL: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/result/86b7f70a-5039-419f-9aeb-8cba09404e92/"
        ],
    )
    screenshotURL: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/screenshots/86b7f70a-5039-419f-9aeb-8cba09404e92.png"
        ],
    )
    source: str = OutputField(example_values=["web"])
    time: str = OutputField(example_values=["2017-08-08T15:04:49.501Z"])
    url: str = OutputField(
        cef_types=["url"], example_values=["https://test.test/index.html"]
    )
    userAgent: str = OutputField(example_values=["TestBrowser/7.0"])
    uuid: str = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["86b7f70a-5039-419f-9aeb-8cba09404e92"],
    )
    visibility: str = OutputField(example_values=["public"])


class CommunityOutput(ActionOutput):
    score: float = OutputField(example_values=[0])
    votesBenign: float = OutputField(example_values=[0])
    votesMalicious: float = OutputField(example_values=[0])
    votesTotal: float = OutputField(example_values=[0])


class EnginesOutput(ActionOutput):
    benignTotal: float = OutputField(example_values=[0])
    enginesTotal: float = OutputField(example_values=[0])
    maliciousTotal: float = OutputField(example_values=[0])
    score: float = OutputField(example_values=[0])


class OverallOutput(ActionOutput):
    hasVerdicts: float = OutputField(example_values=[0])
    malicious: bool = OutputField(example_values=[False])
    score: float = OutputField(example_values=[0])


class UrlscanOutput(ActionOutput):
    malicious: bool = OutputField(example_values=[False])
    score: float = OutputField(example_values=[0])


class VerdictsOutput(ActionOutput):
    community: CommunityOutput
    engines: EnginesOutput
    overall: OverallOutput
    urlscan: UrlscanOutput


class GetReportOutput(ActionOutput):
    data: DataOutput
    lists: ListsOutput
    meta: MetaOutput
    page: PageOutput
    stats: StatsOutput
    submitter: SubmitterOutput
    task: TaskOutput
    verdicts: VerdictsOutput


@app.action(
    description="Query for results of an already completed detonation",
    action_type="investigate",
    params_class=GetReportParams,
    output_class=ReportActionOutput,
    summary_type=AddedTagsSummary,
    view_handler=get_report_view_handler,
)
def get_report(params: GetReportParams, soar: SOARClient, asset: Asset):
    return run_get_report(params, asset)


class LookupDomainParams(Params):
    domain: str = Param(
        description="Domain to lookup", primary=True, cef_types=["domain"]
    )


class PageOutput(ActionOutput):
    asn: str = OutputField(example_values=["ASundefined"])
    asnname: str
    city: str
    country: str = OutputField(example_values=["BG"])
    domain: str = OutputField(cef_types=["domain"], example_values=["test.test"])
    ip: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    mimeType: str = OutputField(example_values=["text/html"])
    ptr: str = OutputField(example_values=["abc.test.test"])
    server: str = OutputField(example_values=["TestServer/1.4"])
    status: str = OutputField(example_values=["200"])
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class StatsOutput(ActionOutput):
    consoleMsgs: float = OutputField(example_values=[1])
    dataLength: float = OutputField(example_values=[1082510])
    encodedDataLength: float = OutputField(example_values=[1002482])
    requests: float = OutputField(example_values=[69])
    uniqCountries: float = OutputField(example_values=[3])
    uniqIPs: float = OutputField(example_values=[5])


class TaskOutput(ActionOutput):
    domain: str = OutputField(example_values=["abc.test.test"])
    method: str = OutputField(example_values=["manual"])
    source: str = OutputField(example_values=["web"])
    time: str = OutputField(example_values=["2017-08-08T15:04:49.501Z"])
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])
    uuid: str = OutputField(example_values=["f04f2a29-d455-4830-874a-88191fb79352"])
    visibility: str = OutputField(example_values=["public"])


class ResultsOutput(ActionOutput):
    id: str = OutputField(
        example_values=["86b7f70a-5039-419f-9aeb-8cba09404e92"], alias="_id"
    )
    indexedAt: str = OutputField(example_values=["2021-02-14T15:16:53.879Z"])
    page: PageOutput
    result: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/api/v1/result/86b7f70a-5039-419f-9aeb-8cba09404e92"
        ],
    )
    screenshot: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png"
        ],
    )
    stats: StatsOutput
    task: TaskOutput
    uniq_countries: float = OutputField(example_values=[2])


class LookupDomainOutput(ActionOutput):
    has_more: bool = OutputField(example_values=[False])
    results: list[ResultsOutput]
    took: float = OutputField(example_values=[25])
    total: float = OutputField(example_values=[1])


@app.action(
    name="lookup domain",
    identifier="hunt_domain",
    description="Find information about a domain at urlscan.io",
    action_type="investigate",
    params_class=LookupDomainParams,
    output_class=LookupActionOutput,
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


class PageOutput(ActionOutput):
    asn: str = OutputField(example_values=["ASundefined"])
    asnname: str = OutputField(example_values=["POWERNET-AS, BG"])
    city: str
    country: str = OutputField(example_values=["BG"])
    domain: str = OutputField(cef_types=["domain"], example_values=["test.test"])
    ip: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    mimeType: str = OutputField(example_values=["text/html"])
    ptr: str = OutputField(example_values=["abc.test.test"])
    server: str = OutputField(example_values=["TestServer/1.4"])
    status: str = OutputField(example_values=["200"])
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class StatsOutput(ActionOutput):
    consoleMsgs: float = OutputField(example_values=[1])
    dataLength: float = OutputField(example_values=[1082510])
    encodedDataLength: float = OutputField(example_values=[1002482])
    requests: float = OutputField(example_values=[69])
    uniqCountries: float = OutputField(example_values=[2])
    uniqIPs: float = OutputField(example_values=[5])


class TaskOutput(ActionOutput):
    domain: str = OutputField(example_values=["abc.test.test"])
    method: str = OutputField(example_values=["manual"])
    source: str = OutputField(example_values=["web"])
    time: str = OutputField(example_values=["2017-08-08T15:04:49.501Z"])
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])
    uuid: str = OutputField(example_values=["f04f2a29-d455-4830-874a-88191fb79352"])
    visibility: str = OutputField(example_values=["public"])


class ResultsOutput(ActionOutput):
    id: str = OutputField(
        example_values=["86b7f70a-5039-419f-9aeb-8cba09404e92"], alias="_id"
    )
    indexedAt: str = OutputField(example_values=["2021-02-25T20:59:59.079Z"])
    page: PageOutput
    result: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/api/v1/result/86b7f70a-5039-419f-9aeb-8cba09404e92"
        ],
    )
    screenshot: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png"
        ],
    )
    stats: StatsOutput
    task: TaskOutput
    uniq_countries: float = OutputField(example_values=[2])


class LookupIpOutput(ActionOutput):
    has_more: bool = OutputField(example_values=[False])
    results: list[ResultsOutput]
    took: float = OutputField(example_values=[77])
    total: float = OutputField(example_values=[104])


@app.action(
    name="lookup ip",
    identifier="hunt_ip",
    description="Find information about an IP address at urlscan.io",
    action_type="investigate",
    params_class=LookupIpParams,
    output_class=LookupActionOutput,
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


class MessageOutput(ActionOutput):
    column: float = OutputField(example_values=[250])
    level: str = OutputField(example_values=["log"])
    line: float = OutputField(example_values=[500])
    source: str = OutputField(example_values=["console-api"])
    text: str = OutputField(
        example_values=[
            "%c%s color: red; background: yellow; font-size: 24px; WARNING!"
        ]
    )
    url: str = OutputField(
        example_values=[
            "/_/mss/boq-identity/_/js/k=boq-identity.ConsentUi.en.wbI8C7EDzao.es5.O/am=CwAQ/d=1/excm=_b,_tp,mainview/ed=1/dg=0/wt=2/rs=AOaEmlFuEZIwaq7Xwoq3xS-5oRO8y6-S_A/m=_b,_tp"
        ]
    )
    timestamp: float = OutputField(example_values=[1721648282157.842])


class ConsoleOutput(ActionOutput):
    message: MessageOutput


class CookiesOutput(ActionOutput):
    domain: str = OutputField(cef_types=["domain"], example_values=["test.test"])
    expires: float = OutputField(example_values=[1517901199000])
    httpOnly: bool
    name: str = OutputField(example_values=["__utmz"])
    path: str = OutputField(example_values=["/"])
    priority: str = OutputField(example_values=["Medium"])
    sameParty: bool = OutputField(example_values=[False])
    sameSite: str
    secure: bool
    session: bool
    size: float = OutputField(example_values=[76])
    sourcePort: float = OutputField(example_values=[443])
    sourceScheme: str = OutputField(example_values=["Secure"])
    value: str = OutputField(
        example_values=[
            "215733128.1502133199.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)"
        ]
    )
    partitionKey: str = OutputField(example_values=["https://watermelongame.com"])


class GlobalsOutput(ActionOutput):
    prop: str = OutputField(example_values=["onbeforexrselect"])
    type: str = OutputField(example_values=["object"])


class LinksOutput(ActionOutput):
    href: str = OutputField(cef_types=["url"], example_values=["http://test.test"])
    text: str = OutputField(example_values=["stor perde"])


class InitiatorinfoOutput(ActionOutput):
    host: str = OutputField(example_values=["www.test.test"])
    type: str = OutputField(example_values=["parser"])
    url: str = OutputField(cef_types=["url"], example_values=["http://test.test"])


class CallframesOutput(ActionOutput):
    columnNumber: float = OutputField(example_values=[493])
    functionName: str = OutputField(example_values=["zg"])
    lineNumber: float = OutputField(example_values=[532])
    scriptId: str = OutputField(example_values=["8"])
    url: str = OutputField(example_values=["https://abc.test.test/s/player/"])


class StackOutput(ActionOutput):
    callFrames: list[CallframesOutput]


class InitiatorOutput(ActionOutput):
    columnNumber: float = OutputField(example_values=[0])
    lineNumber: float = OutputField(example_values=[0])
    stack: StackOutput
    type: str = OutputField(example_values=["other"])
    url: str = OutputField(example_values=["https://abc.test.test/embed/abc"])


class HeadersOutput(ActionOutput):
    Accept_Ranges: str = OutputField(example_values=["bytes"], alias="Accept-Ranges")
    Access_Control_Allow_Credentials: str = OutputField(
        example_values=["true"], alias="Access-Control-Allow-Credentials"
    )
    Access_Control_Allow_Headers: str = OutputField(
        example_values=["origin,range,hdntl,hdnts"],
        alias="Access-Control-Allow-Headers",
    )
    Access_Control_Allow_Methods: str = OutputField(
        example_values=["GET,POST,OPTIONS"], alias="Access-Control-Allow-Methods"
    )
    Access_Control_Allow_Origin: str = OutputField(
        example_values=["*"], alias="Access-Control-Allow-Origin"
    )
    Access_Control_Expose_Headers: str = OutputField(
        example_values=["Content-Range, X-ATLAS-MARKERS"],
        alias="Access-Control-Expose-Headers",
    )
    Access_Control_Max_Age: str = OutputField(
        example_values=["86400"], alias="Access-Control-Max-Age"
    )
    Age: str = OutputField(example_values=["0"])
    Alt_Svc: str = OutputField(
        example_values=[
            'h3-29=":443"; ma=93600,h3-Q050=":443"; ma=93600,quic=":443"; ma=93600; v="46,43"'
        ],
        alias="Alt-Svc",
    )
    Cache_Control: str = OutputField(
        example_values=["no-cache, no-store, must-revalidate"], alias="Cache-Control"
    )
    Connection: str = OutputField(example_values=["Keep-Alive"])
    Content_Encoding: str = OutputField(
        example_values=["gzip"], alias="Content-Encoding"
    )
    Content_Length: str = OutputField(example_values=["10586"], alias="Content-Length")
    Content_Security_Policy_Report_Only: str = OutputField(
        example_values=[
            "default-src 'none'; block-all-mixed-content; connect-src https://*.abc.test.test https://*.abc.abc.test 'self'; frame-ancestors 'none'; img-src 'self' https://test.img https://*.img.test; media-src 'none'; script-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q'; style-src 'self' 'nonce-iXnashVb/x3vqerVfc25bndc5thiav8Q';"
        ],
        alias="Content-Security-Policy-Report-Only",
    )
    Content_Type: str = OutputField(example_values=["text/html"], alias="Content-Type")
    Date: str = OutputField(example_values=["Mon, 07 Aug 2017 19:13:18 GMT"])
    ETag: str = OutputField(example_values=['"5c17f0-1bf5-4bc7627477580"'])
    Etag: str = OutputField(example_values=['"test91705564909da7f9eaf749dbbfbb1"'])
    Expect_CT: str = OutputField(
        example_values=[
            'max-age=31536000, report-uri="http://abc.test.test/beacon/csp?src=test-expect-ct-report-only"'
        ],
        alias="Expect-CT",
    )
    Expires: str = OutputField(example_values=["0"])
    Keep_Alive: str = OutputField(
        example_values=["timeout=1, max=99"], alias="Keep-Alive"
    )
    Last_Modified: str = OutputField(
        example_values=["Fri, 30 Mar 2012 13:52:38 GMT"], alias="Last-Modified"
    )
    P3P: str = OutputField(
        example_values=['CP="NON DSP COR ADMa OUR IND UNI COM NAV INT"']
    )
    Pragma: str = OutputField(example_values=["no-cache"])
    Public_Key_Pins_Report_Only: str = OutputField(
        example_values=[
            'max-age=2592000; pin-sha256="testyxl4A1/XHrKNBmc8bTk7y4FB/GLJuNAzCqY="; pin-sha256="I/Lt/testanjCvj5EqXls2lOaThEA0H2Bg4BT/o="; pin-sha256="testBWM9UZfyddvDfoxL+8lpNyoUB2ptGtn0fv6G2Q="; pin-sha256="test/qfTwq3lFNd3IpaqLHZbh2ZNCLluVzmeNkcpw="; pin-sha256="testIOVNa9ihaBciRC7XHjliYS9VwUGOIud4PB18="; pin-sha256="testXyFXFkWm61cF4HPW8S0srS9j0aSqN0k4AP+4A="; pin-sha256="testzEBnELx/9lOEQ2e6OZO/QNb6VSSX2XHA3E7A="; pin-sha256="testvh0OioIruIfF4kMPnBqrS2rdiVPl/s2uC/CY="; pin-sha256="r/testpVdm+u/ko/xzOMo1bk4TyHIlByibiA5E="; pin-sha256="testwDOxcBXrQcntwu+kYFiVkOaezL0WYEZ3anJc="; includeSubdomains; report-uri="http://abc.test.test/beacon/csp?src=test-hpkp-report-only"'  # pragma: allowlist secret
        ],
        alias="Public-Key-Pins-Report-Only",
    )
    Referrer_Policy: str = OutputField(
        example_values=["strict-origin-when-cross-origin"], alias="Referrer-Policy"
    )
    Server: str = OutputField(example_values=["TestServer/1.4"])
    Strict_Transport_Security: str = OutputField(
        example_values=["max-age=31536000; includeSubDomains"],
        alias="Strict-Transport-Security",
    )
    Timing_Allow_Origin: str = OutputField(
        example_values=["*"], alias="Timing-Allow-Origin"
    )
    Transfer_Encoding: str = OutputField(
        example_values=["chunked"], alias="Transfer-Encoding"
    )
    Vary: str = OutputField(example_values=["Accept-Encoding,User-Agent"])
    Via: str = OutputField(
        example_values=["1.1 9c157874a076ffdde5f5a44371f3a1.test.test"]
    )
    X_Amz_Cf_Id: str = OutputField(
        example_values=[
            "wznqqSUHDRcnnyCbk9Dimhb-WD6cpBAdjEUd2PE58mwE7HIv2BIw=="  # pragma: allowlist secret
        ],
        alias="X-Amz-Cf-Id",
    )
    X_Amz_Cf_Pop: str = OutputField(example_values=["VIE50-C1"], alias="X-Amz-Cf-Pop")
    X_Cache: str = OutputField(example_values=["HIT"], alias="X-Cache")
    X_Content_Type_Options: str = OutputField(
        example_values=["nosniff"], alias="X-Content-Type-Options"
    )
    X_DIS_Request_ID: str = OutputField(
        example_values=["9137843c7fc8d206d8a5f450cc63f525"],  # pragma: allowlist secret
        alias="X-DIS-Request-ID",
    )
    X_Frame_Options: str = OutputField(example_values=["DENY"], alias="X-Frame-Options")
    X_LLID: str = OutputField(
        cef_types=["md5"],
        example_values=["7d093909d3419b732aeaa85b2f081282"],  # pragma: allowlist secret
        alias="X-LLID",
    )
    X_Powered_By: str = OutputField(example_values=["PHP/5.2.17"], alias="X-Powered-By")
    X_XSS_Protection: str = OutputField(
        example_values=["1; mode=block"], alias="X-XSS-Protection"
    )
    accept_ranges: str = OutputField(example_values=["bytes"], alias="accept-ranges")
    access_control_allow_credentials: str = OutputField(
        example_values=["true"], alias="access-control-allow-credentials"
    )
    access_control_allow_headers: str = OutputField(
        example_values=["X-Playlog-Web"], alias="access-control-allow-headers"
    )
    access_control_allow_method: str = OutputField(
        example_values=["OPTIONS"], alias="access-control-allow-method"
    )
    access_control_allow_methods: str = OutputField(
        example_values=["GET"], alias="access-control-allow-methods"
    )
    access_control_allow_origin: str = OutputField(
        cef_types=["url"], example_values=["*"], alias="access-control-allow-origin"
    )
    access_control_expose_headers: str = OutputField(
        example_values=["X-FB-Content-MD5"], alias="access-control-expose-headers"
    )
    age: str = OutputField(example_values=["734"])
    alt_svc: str = OutputField(
        example_values=['quic=":443"; ma=2592000; v="39,38,37,36,35"'], alias="alt-svc"
    )
    ats_carp_promotion: str = OutputField(
        example_values=["1"], alias="ats-carp-promotion"
    )
    cache_control: str = OutputField(
        example_values=["private, max-age=1800, stale-while-revalidate=1800"],
        alias="cache-control",
    )
    content_disposition: str = OutputField(
        example_values=[
            "attachment; filename=\"response.bin\"; filename*=UTF-8''response.bin"
        ],
        alias="content-disposition",
    )
    content_encoding: str = OutputField(
        example_values=["gzip"], alias="content-encoding"
    )
    content_length: str = OutputField(example_values=["16022"], alias="content-length")
    content_md5: str = OutputField(
        example_values=["9Bs4q2xta3z6+p7pgFz0Ww=="], alias="content-md5"
    )
    content_security_policy: str = OutputField(
        example_values=[
            "default-src * data: blob:;script-src *.test.test *.test2.test 127.0.0.1:* 'unsafe-inline' 'unsafe-eval' 'self';"
        ],
        alias="content-security-policy",
    )
    content_security_policy_report_only: str = OutputField(
        example_values=[
            "default-src 'self'; report-uri https://abc.test.test/beacon/csp?src=test"
        ],
        alias="content-security-policy-report-only",
    )
    content_type: str = OutputField(
        example_values=["application/javascript; charset=utf-8"], alias="content-type"
    )
    cross_origin_opener_policy_report_only: str = OutputField(
        example_values=['unsafe-none; report-to="ConsentUi"'],
        alias="cross-origin-opener-policy-report-only",
    )
    cross_origin_resource_policy: str = OutputField(
        example_values=["same-site"], alias="cross-origin-resource-policy"
    )
    date: str = OutputField(example_values=["Mon, 07 Aug 2017 19:13:18 GMT"])
    etag: str = OutputField(example_values=['"test4c7de07fe8def6029af1192b2d"'])
    expect_ct: str = OutputField(
        example_values=[
            'max-age=31536000, report-uri="http://cabc.test.test/beacon/csp?src=test-expect-ct-report-only"'
        ],
        alias="expect-ct",
    )
    expires: str = OutputField(example_values=["Mon, 07 Aug 2017 19:13:18 GMT"])
    last_modified: str = OutputField(
        example_values=["Tue, 01 Aug 2017 03:25:32 GMT"], alias="last-modified"
    )
    link: str = OutputField(
        example_values=["<https://abc.test.test>; rel=preconnect; crossorigin"]
    )
    p3p: str = OutputField(
        example_values=[
            'CP="This is not a P3P policy! See https://support.test.test for more info."'
        ]
    )
    pragma: str = OutputField(example_values=["no-cache"])
    public_key_pins_report_only: str = OutputField(
        example_values=[
            'max-age=500; pin-sha256="testIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18="; pin-sha256="r/testeEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E="; pin-sha256="test2cbkZhZ82+JgmRUyGMoAeozA+BSXVXQWB8XWQ="; report-uri="http://abc.test.test/"'  # pragma: allowlist secret
        ],
        alias="public-key-pins-report-only",
    )
    referrer_policy: str = OutputField(
        example_values=["no-referrer-when-downgrade"], alias="referrer-policy"
    )
    report_to: str = OutputField(
        example_values=[
            '{"group":"ConsentUi","max_age":2592000,"endpoints":[{"url":"https://abc.test.test/csp/external"}]}'
        ],
        alias="report-to",
    )
    server: str = OutputField(example_values=["ESF"])
    set_cookie: str = OutputField(
        example_values=[
            "YSC=a-rkoUxJ3S4; Domain=.test.test; Path=/; Secure; HttpOnly; SameSite=none VISITOR_INFO1_LIVE=gH7gS_3ehDQ; Domain=.test.test; Expires=Wed, 25-Aug-2021 05:33:56 GMT; Path=/; Secure; HttpOnly; SameSite=none CONSENT=PENDING+007; expires=Fri, 01-Jan-2038 00:00:00 GMT; path=/; domain=.test.test"
        ],
        alias="set-cookie",
    )
    status: str = OutputField(example_values=["200"])
    strict_transport_security: str = OutputField(
        example_values=["max-age=31536000"], alias="strict-transport-security"
    )
    timing_allow_origin: str = OutputField(
        example_values=["*"], alias="timing-allow-origin"
    )
    vary: str = OutputField(example_values=["Accept-Encoding"])
    via: str = OutputField(example_values=["1.1 73f3a231569992949c078c30859.test.test"])
    x_amz_cf_id: str = OutputField(
        example_values=[
            "2fSWemgLL1daViXpR9QBZrtaZnsqQpggTXr_vB__XSQqPkjy_r5Q=="  # pragma: allowlist secret
        ],
        alias="x-amz-cf-id",
    )
    x_amz_cf_pop: str = OutputField(example_values=["FRA53-C1"], alias="x-amz-cf-pop")
    x_amz_id_2: str = OutputField(
        example_values=[
            "ha+gqKNXBkV1gqr4AHswgx1OZSCdM7otKBZCL/JFLsojoWZn3VruarvQAhNV9ejI7FMh7PalI="  # pragma: allowlist secret
        ],
        alias="x-amz-id-2",
    )
    x_amz_request_id: str = OutputField(
        example_values=["2KMY2R40Y5WJNG70"], alias="x-amz-request-id"
    )
    x_amz_server_side_encryption: str = OutputField(
        example_values=["AES256"], alias="x-amz-server-side-encryption"
    )
    x_cache: str = OutputField(example_values=["Hit from TestCloud"], alias="x-cache")
    x_content_type_options: str = OutputField(
        example_values=["nosniff"], alias="x-content-type-options"
    )
    x_fb_content_md5: str = OutputField(
        cef_types=["md5"],
        example_values=["0bd61dc947229e72968554f0c9fb51db"],  # pragma: allowlist secret
        alias="x-fb-content-md5",
    )
    x_fb_debug: str = OutputField(
        example_values=[
            "hUiq7Iq/Mt3plXYg3YAU6tS/1K06AainVmY+EU3e6s9L1+7n8CrQFf6Va+EHLQ2tSVCOePLr3hQ5PcEZ6c8R/Q=="  # pragma: allowlist secret
        ],
        alias="x-fb-debug",
    )
    x_frame_options: str = OutputField(
        example_values=["SAMEORIGIN"], alias="x-frame-options"
    )
    x_ua_compatible: str = OutputField(
        example_values=["IE=edge, chrome=1"], alias="x-ua-compatible"
    )
    x_xss_protection: str = OutputField(
        example_values=["1; mode=block"], alias="x-xss-protection"
    )
    accept_ch: str = OutputField(
        example_values=[
            "Sec-CH-UA-Platform Sec-CH-UA-Platform-Version Sec-CH-UA-Full-Version Sec-CH-UA-Arch Sec-CH-UA-Model Sec-CH-UA-Bitness Sec-CH-UA-Full-Version-List Sec-CH-UA-WoW64"
        ],
        alias="accept-ch",
    )
    permissions_policy: str = OutputField(
        example_values=["unload=()"], alias="permissions-policy"
    )
    cross_origin_opener_policy: str = OutputField(
        example_values=['same-origin-allow-popups; report-to="gws"'],
        alias="cross-origin-opener-policy",
    )
    version: str = OutputField(example_values=["652602471"])
    server_timing: str = OutputField(
        example_values=["gfet4t7; dur=12"], alias="server-timing"
    )
    access_control_max_age: str = OutputField(
        example_values=["3600"], alias="access-control-max-age"
    )
    nel: str = OutputField(
        example_values=['{"success_fraction":0,"report_to":"cf-nel","max_age":604800}']
    )
    cf_ray: str = OutputField(example_values=["8a73b0909a9e975f-FRA"], alias="cf-ray")
    x_robots_tag: str = OutputField(example_values=["noindex"], alias="x-robots-tag")
    cf_cache_status: str = OutputField(example_values=["HIT"], alias="cf-cache-status")
    x_middleton_display: str = OutputField(
        example_values=["sol-js"], alias="x-middleton-display"
    )
    edge_control: str = OutputField(
        example_values=["cache-maxage=60m,downstream-ttl=60m"], alias="edge-control"
    )
    x_sol: str = OutputField(example_values=["middleton"], alias="x-sol")
    display: str = OutputField(example_values=["staticcontent_sol"])
    x_amz_version_id: str = OutputField(
        example_values=["r5.lR.LJ66XEXzxUUVo7iMemjL_F_GoE"], alias="x-amz-version-id"
    )
    cf_bgj: str = OutputField(example_values=["minify"], alias="cf-bgj")
    apigw_requestid: str = OutputField(
        example_values=["bUMp6iOMoAMEbPQ="], alias="apigw-requestid"
    )
    server_processing_duration_in_ticks: str = OutputField(
        example_values=["154170"], alias="server-processing-duration-in-ticks"
    )
    allow: str = OutputField(example_values=["POST, OPTIONS, GET"])
    x_server: str = OutputField(example_values=["10.45.18.91"], alias="x-server")
    debug: str = OutputField(example_values=["NON-OPTIONS"])
    x_goog_hash: str = OutputField(
        example_values=["crc32c=cpEfJQ==, md5=rUsPYG4PhGW8TEwXCzfhow=="],
        alias="x-goog-hash",
    )
    x_goog_generation: str = OutputField(
        example_values=["1620242732037093"], alias="x-goog-generation"
    )
    x_goog_storage_class: str = OutputField(
        example_values=["MULTI_REGIONAL"], alias="x-goog-storage-class"
    )
    x_guploader_uploadid: str = OutputField(
        example_values=[
            "ABPtcPovIz6nZtqULu9hGQBSVbC6_z8lEyamrIA64gM0CArHcTLURzj7EtelAkaCkOXM4KyL70M"  # pragma: allowlist secret
        ],
        alias="x-guploader-uploadid",
    )
    x_goog_metageneration: str = OutputField(
        example_values=["5"], alias="x-goog-metageneration"
    )
    x_goog_stored_content_length: str = OutputField(
        example_values=["43"], alias="x-goog-stored-content-length"
    )
    x_goog_stored_content_encoding: str = OutputField(
        example_values=["identity"], alias="x-goog-stored-content-encoding"
    )
    X_Robots_Tag: str = OutputField(example_values=["noindex"], alias="X-Robots-Tag")
    Permissions_Policy: str = OutputField(
        example_values=["browsing-topics=()"], alias="Permissions-Policy"
    )
    x_nbr: str = OutputField(example_values=["1"], alias="x-nbr")
    x_envoy_upstream_service_time: str = OutputField(
        example_values=["0"], alias="x-envoy-upstream-service-time"
    )
    observe_browsing_topics: str = OutputField(
        example_values=["?1"], alias="observe-browsing-topics"
    )
    google_creative_id: str = OutputField(
        example_values=["-2"], alias="google-creative-id"
    )
    google_lineitem_id: str = OutputField(
        example_values=["-2"], alias="google-lineitem-id"
    )
    google_mediationtag_id: str = OutputField(
        example_values=["-2"], alias="google-mediationtag-id"
    )
    google_mediationgroup_id: str = OutputField(
        example_values=["-2"], alias="google-mediationgroup-id"
    )
    x_cache_status: str = OutputField(example_values=["HIT"], alias="x-cache-status")
    x_rgw_object_type: str = OutputField(
        example_values=["Normal"], alias="x-rgw-object-type"
    )
    x_mnet_hl2: str = OutputField(example_values=["E"], alias="x-mnet-hl2")
    cross_origin_embedder_policy: str = OutputField(
        example_values=["require-corp"], alias="cross-origin-embedder-policy"
    )
    cf_polished: str = OutputField(
        example_values=["origSize=1018"], alias="cf-polished"
    )


class RequestheadersOutput(ActionOutput):
    authority: str = OutputField(example_values=["abc.test.test"], alias=":authority")
    method: str = OutputField(example_values=["GET"], alias=":method")
    path: str = OutputField(example_values=["/"], alias=":path")
    scheme: str = OutputField(
        cef_types=["url"], example_values=["https"], alias=":scheme"
    )
    Accept: str = OutputField(
        example_values=[
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
        ]
    )
    Accept_Encoding: str = OutputField(
        example_values=["gzip, deflate, br"], alias="Accept-Encoding"
    )
    Accept_Language: str = OutputField(
        example_values=["en-US"], alias="Accept-Language"
    )
    Cache_Control: str = OutputField(example_values=["no-cache"], alias="Cache-Control")
    Connection: str = OutputField(example_values=["keep-alive"])
    Cookie: str = OutputField(
        example_values=["B=dv5klk1g9hcet&b=3&s=t9; GUCS=AVkRFB1g"]
    )
    Host: str = OutputField(example_values=["abc.test.test"])
    Pragma: str = OutputField(example_values=["no-cache"])
    Referer: str = OutputField(example_values=["https://www.test.test/"])
    Sec_Fetch_Dest: str = OutputField(
        example_values=["document"], alias="Sec-Fetch-Dest"
    )
    Sec_Fetch_Mode: str = OutputField(
        example_values=["navigate"], alias="Sec-Fetch-Mode"
    )
    Sec_Fetch_Site: str = OutputField(alias="Sec-Fetch-Site")
    Sec_Fetch_User: str = OutputField(alias="Sec-Fetch-User")
    Upgrade_Insecure_Requests: str = OutputField(
        example_values=["1"], alias="Upgrade-Insecure-Requests"
    )
    User_Agent: str = OutputField(
        example_values=["TestBrowser/7.0"], alias="User-Agent"
    )
    accept: str = OutputField(
        example_values=[
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
        ]
    )
    accept_encoding: str = OutputField(
        example_values=["gzip, deflate, br"], alias="accept-encoding"
    )
    accept_language: str = OutputField(
        example_values=["en-US"], alias="accept-language"
    )
    cache_control: str = OutputField(example_values=["no-cache"], alias="cache-control")
    content_length: str = OutputField(example_values=["133"], alias="content-length")
    content_type: str = OutputField(
        example_values=["application/x-www-form-urlencoded;charset=UTF-8"],
        alias="content-type",
    )
    cookie: str = OutputField(example_values=["CONSENT=PENDING+166"])
    origin: str = OutputField(
        cef_types=["url"], example_values=["https://abc.test.test"]
    )
    pragma: str = OutputField(example_values=["no-cache"])
    referer: str = OutputField(
        cef_types=["url"], example_values=["https://abc.test.test/"]
    )
    sec_fetch_dest: str = OutputField(
        example_values=["document"], alias="sec-fetch-dest"
    )
    sec_fetch_mode: str = OutputField(
        example_values=["navigate"], alias="sec-fetch-mode"
    )
    sec_fetch_site: str = OutputField(alias="sec-fetch-site")
    sec_fetch_user: str = OutputField(example_values=["?1"], alias="sec-fetch-user")
    upgrade_insecure_requests: str = OutputField(
        example_values=["1"], alias="upgrade-insecure-requests"
    )
    user_agent: str = OutputField(
        example_values=["TestBrowser/7.0"], alias="user-agent"
    )
    x_same_domain: str = OutputField(
        cef_types=["domain"], example_values=["1"], alias="x-same-domain"
    )


class SignedcertificatetimestamplistOutput(ActionOutput):
    hashAlgorithm: str = OutputField(example_values=["SHA-256"])
    logDescription: str = OutputField(example_values=["Test 'test' log"])
    logId: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "A4B90990B418581487BB13A2CC67700A3C359804F91BDFB8E377CD0EC80DDC10"  # pragma: allowlist secret
        ],
    )
    origin: str = OutputField(example_values=["TLS extension"])
    signatureAlgorithm: str = OutputField(example_values=["ECDSA"])
    signatureData: str = OutputField(
        example_values=[
            "304502201B93510379EBD837E19EA9C684D5EF8D8E777A9A6D0B094AD30465C394FEFCEA0221008622A01AE4C1FDFA376F53FE0E9231E95E6FAE68E47559DA04F147E2461DC1C8"  # pragma: allowlist secret
        ]
    )
    status: str = OutputField(example_values=["Verified"])
    timestamp: float = OutputField(example_values=[1500976811010])


class SecuritydetailsOutput(ActionOutput):
    certificateId: float = OutputField(example_values=[0])
    certificateTransparencyCompliance: str = OutputField(example_values=["unknown"])
    cipher: str = OutputField(example_values=["AES_128_GCM"])
    issuer: str = OutputField(example_values=["Test Authority"])
    keyExchange: str = OutputField(example_values=["ECDHE_RSA"])
    keyExchangeGroup: str = OutputField(example_values=["X25519"])
    protocol: str = OutputField(example_values=["TLS 1.2"])
    sanList: str = OutputField(example_values=["test.test"])
    signedCertificateTimestampList: list[SignedcertificatetimestamplistOutput]
    subjectName: str = OutputField(example_values=["*.apis.test.test"])
    validFrom: float = OutputField(example_values=[1500972335])
    validTo: float = OutputField(example_values=[1508228880])
    encryptedClientHello: bool
    serverSignatureAlgorithm: float = OutputField(example_values=[1027])


class TimingOutput(ActionOutput):
    beginNavigation: str = OutputField(example_values=["2017-08-07T19:13:17.987Z"])
    domContentEventFired: str = OutputField(example_values=["2017-08-07T19:13:19.165Z"])
    frameNavigated: str = OutputField(example_values=["2017-08-07T19:13:19.897Z"])
    frameStartedLoading: str = OutputField(example_values=["2017-08-07T19:13:19.902Z"])
    frameStoppedLoading: str = OutputField(example_values=["2017-08-07T19:13:20.116Z"])
    loadEventFired: str = OutputField(example_values=["2017-08-07T19:13:19.897Z"])


class RedirectresponseOutput(ActionOutput):
    asn: AsnOutput
    encodedDataLength: float = OutputField(example_values=[1132])
    fromPrefetchCache: bool = OutputField(example_values=[False])
    geoip: GeoipOutput
    headers: HeadersOutput
    mimeType: str = OutputField(example_values=["text/html"])
    protocol: str = OutputField(cef_types=["url"], example_values=["http/1.1"])
    rdns: RdnsOutput
    remoteIPAddress: str = OutputField(
        cef_types=["ip", "ipv6"], example_values=["[2a00:1288:110:c305::1:8000]"]
    )
    remotePort: float = OutputField(example_values=[80])
    requestHeaders: RequestheadersOutput
    responseTime: float = OutputField(example_values=[1620619741065.401])
    securityDetails: SecuritydetailsOutput
    securityState: str = OutputField(example_values=["insecure"])
    status: float = OutputField(example_values=[301])
    statusText: str = OutputField(example_values=["Moved Permanently"])
    timing: TimingOutput
    url: str = OutputField(cef_types=["url"], example_values=["http://abc.test.test/"])
    charset: str
    alternateProtocolUsage: str = OutputField(
        example_values=["TESTalternativeJobWonWithoutRace"]
    )


class PostdataentriesOutput(ActionOutput):
    bytes: str


class RequestOutput(ActionOutput):
    headers: HeadersOutput
    initialPriority: str = OutputField(example_values=["VeryHigh"])
    method: str = OutputField(example_values=["GET"])
    mixedContentType: str
    referrerPolicy: str = OutputField(
        example_values=["strict-origin-when-cross-origin"]
    )
    url: str = OutputField(cef_types=["url"], example_values=["http://abc.test.test/"])
    isSameSite: bool


class AsnOutput(ActionOutput):
    asn: str = OutputField(example_values=["43260"])
    country: str = OutputField(example_values=["TR"])
    date: str = OutputField(example_values=["2007-07-04"])
    description: str = OutputField(example_values=["DGN, TR"])
    ip: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    name: str = OutputField(example_values=["DGN"])
    registrar: str = OutputField(example_values=["ripencc"])
    route: str = OutputField(example_values=["2a00:1288:110::/46"])


class GeoipOutput(ActionOutput):
    area: float = OutputField(example_values=[100])
    city: str = OutputField(example_values=["Bursa"])
    country: str = OutputField(example_values=["TR"])
    country_name: str = OutputField(example_values=["Turkey"])
    eu: str = OutputField(example_values=["0"])
    ll: float = OutputField(example_values=[-8])
    metro: float = OutputField(example_values=[0])
    range: float = OutputField(example_values=[1167286271])
    region: str = OutputField(example_values=["16"])
    timezone: str = OutputField(example_values=["Europe/London"])
    zip: float = OutputField(example_values=[16245])


class RdnsOutput(ActionOutput):
    ip: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    ptr: str = OutputField(example_values=["abc.test.test"])


class RequestsOutput(ActionOutput):
    initiatorInfo: InitiatorinfoOutput
    request: RequestOutput
    requests: list[RequestsOutput]
    response: ResponseOutput


class AbpOutput(ActionOutput):
    data: list[DataOutput]
    state: str = OutputField(example_values=["done"])


class CorserrorstatusOutput(ActionOutput):
    corsError: str = OutputField(example_values=["MissingAllowOriginHeader"])
    failedParameter: str


class FailedOutput(ActionOutput):
    canceled: bool
    errorText: str
    requestId: str = OutputField(example_values=["24696.156"])
    timestamp: float = OutputField(example_values=[25061896.916161])
    type: str = OutputField(example_values=["Document"])
    corsErrorStatus: CorserrorstatusOutput


class HashmatchesOutput(ActionOutput):
    file: str = OutputField(example_values=["mediaelement/2.0.0/jquery.js"])
    project: str = OutputField(example_values=["mediaelement"])
    project_url: str = OutputField(
        cef_types=["url"], example_values=["https://test.test"]
    )
    source: str = OutputField(example_values=["Test Inc."])
    url: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class SecurityheadersOutput(ActionOutput):
    name: str = OutputField(example_values=["Strict-Transport-Security"])
    value: str = OutputField(example_values=["max-age=31536000"])


class ResponseOutput(ActionOutput):
    abp: AbpOutput
    asn: AsnOutput
    dataLength: float = OutputField(example_values=[48900])
    encodedDataLength: float = OutputField(example_values=[10586])
    failed: FailedOutput
    geoip: GeoipOutput
    hash: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "90e62949116352899d321b982d3c8dd6e269538d9832a82e86b6f08b10f54883"  # pragma: allowlist secret
        ],
    )
    hashmatches: list[HashmatchesOutput]
    rdns: RdnsOutput
    requestId: str = OutputField(example_values=["24696.1"])
    response: ResponseOutput
    size: float = OutputField(example_values=[48900])
    type: str = OutputField(example_values=["Document"])
    hasExtraInfo: bool


class DataOutput(ActionOutput):
    rank: float = OutputField(example_values=[10])
    hostname: str = OutputField(example_values=["www.google.com"])


class FielderrorsOutput(ActionOutput):
    location: str = OutputField(example_values=["body"])
    msg: str = OutputField(example_values=["must be between 5 and 2083 characters"])
    param: str
    value: str = OutputField(example_values=["123"])


class CertificatesOutput(ActionOutput):
    issuer: str = OutputField(example_values=["Test Authority"])
    sanList: str = OutputField(example_values=["test.test"])
    subjectName: str = OutputField(example_values=["*.apis.test.test"])
    validFrom: float = OutputField(example_values=[1500972335])
    validTo: float = OutputField(example_values=[1508228880])


class ListsOutput(ActionOutput):
    asns: str = OutputField(example_values=["32934"])
    certificates: list[CertificatesOutput]
    countries: str = OutputField(example_values=["IE"])
    domains: str = OutputField(example_values=["accounts.test.test"])
    hashes: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "548f2d6f4d0d820c6c5ffbeffcbd7f0e73193e2932eefe542accc84762deec87"  # pragma: allowlist secret
        ],
    )
    ips: str = OutputField(example_values=["2a03:2880:f11c:8183:face:b00c:0:25de"])
    linkDomains: str = OutputField(example_values=["test.test"])
    servers: str = OutputField(example_values=["ESF"])
    urls: str = OutputField(cef_types=["url"], example_values=["https://test.test"])


class CdnjsOutput(ActionOutput):
    data: list[DataOutput]
    state: str = OutputField(example_values=["done"])


class DoneOutput(ActionOutput):
    data: DataOutput
    state: str = OutputField(example_values=["done"])


class GsbOutput(ActionOutput):
    state: str = OutputField(example_values=["done"])


class CategoriesOutput(ActionOutput):
    name: str = OutputField(example_values=["Web Frameworks"])
    priority: float = OutputField(example_values=[7])


class ConfidenceOutput(ActionOutput):
    pattern: str = OutputField(
        example_values=[
            "bootstrap(?:[^>]*?([0-9a-fA-F]{7,40}|[\\d]+(?:.[\\d]+(?:.[\\d]+)?)?)|)[^>]*?(?:\\.min)?\\.js"
        ]
    )
    confidence: float = OutputField(example_values=[100])


class WappaOutput(ActionOutput):
    state: str = OutputField(example_values=["done"])
    data: list[DataOutput]


class UmbrellaOutput(ActionOutput):
    data: list[DataOutput]


class ProcessorsOutput(ActionOutput):
    abp: AbpOutput
    asn: AsnOutput
    cdnjs: CdnjsOutput
    done: DoneOutput
    geoip: GeoipOutput
    gsb: GsbOutput
    rdns: RdnsOutput
    wappa: WappaOutput
    umbrella: UmbrellaOutput


class MetaOutput(ActionOutput):
    processors: ProcessorsOutput


class OptionsOutput(ActionOutput):
    useragent: str = OutputField(example_values=["TestBrowser/7.0"])


class PageOutput(ActionOutput):
    asn: str = OutputField(example_values=["AS43260"])
    asnname: str = OutputField(example_values=["DGN, TR"])
    city: str = OutputField(example_values=["Bursa"])
    country: str = OutputField(example_values=["TR"])
    domain: str = OutputField(cef_types=["domain"], example_values=["www.test.test"])
    ip: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    ptr: str = OutputField(example_values=["abc.test.test"])
    server: str = OutputField(example_values=["TestServer/1.4"])
    url: str = OutputField(cef_types=["url"], example_values=["http://test.test"])
    title: str = OutputField(example_values=["Google"])
    status: str = OutputField(example_values=["200"])
    mimeType: str = OutputField(example_values=["text/html"])
    tlsIssuer: str = OutputField(example_values=["WR2"])
    apexDomain: str = OutputField(example_values=["google.com"])
    redirected: str = OutputField(example_values=["sub-domain"])
    tlsAgeDays: float = OutputField(example_values=[28])
    tlsValidDays: float = OutputField(example_values=[83])
    tlsValidFrom: str = OutputField(example_values=["2024-06-24T06:35:44.000Z"])
    umbrellaRank: float = OutputField(example_values=[10])


class DomainstatsOutput(ActionOutput):
    count: float = OutputField(example_values=[55])
    countries: str = OutputField(example_values=["IE"])
    domain: str = OutputField(cef_types=["domain"], example_values=["www.test.test"])
    encodedSize: float = OutputField(example_values=[2042170])
    index: float = OutputField(example_values=[0])
    initiators: str = OutputField(example_values=["apis.test.test"])
    ips: str = OutputField(example_values=["[2a03:2880:f006:21:face:b00c:0:3]"])
    redirects: float = OutputField(example_values=[0])
    size: float = OutputField(example_values=[2410398])


class IpstatsOutput(ActionOutput):
    asn: AsnOutput
    count: str
    countries: str = OutputField(example_values=["IE"])
    domains: str = OutputField(example_values=["www.test.test"])
    encodedSize: float = OutputField(example_values=[2042170])
    geoip: GeoipOutput
    index: float = OutputField(example_values=[0])
    ip: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    ipv6: bool
    rdns: RdnsOutput
    redirects: float = OutputField(example_values=[3])
    requests: float = OutputField(example_values=[55])
    size: float = OutputField(example_values=[2410398])


class ProtocolstatsOutput(ActionOutput):
    count: float = OutputField(example_values=[55])
    countries: str = OutputField(example_values=["IE"])
    encodedSize: float = OutputField(example_values=[2042170])
    ips: str = OutputField(example_values=["[2a03:2880:f11c:8183:face:b00c:0:25de]"])
    protocol: str = OutputField(cef_types=["url"], example_values=["http/1.1"])
    size: float = OutputField(example_values=[2410398])


class SubdomainsOutput(ActionOutput):
    country: str = OutputField(example_values=["GB"])
    domain: str = OutputField(cef_types=["domain"], example_values=["apis"])
    failed: bool


class RegdomainstatsOutput(ActionOutput):
    count: float = OutputField(example_values=[55])
    encodedSize: float = OutputField(example_values=[2042170])
    index: float = OutputField(example_values=[0])
    ips: str = OutputField(example_values=["[2a03:2880:f006:21:face:b00c:0:3]"])
    redirects: float = OutputField(example_values=[4])
    regDomain: str = OutputField(cef_types=["domain"], example_values=["test.test"])
    size: float = OutputField(example_values=[2410398])
    subDomains: list[SubdomainsOutput]


class ResourcestatsOutput(ActionOutput):
    compression: str = OutputField(example_values=["1.0"])
    count: float = OutputField(example_values=[40])
    countries: str = OutputField(example_values=["TR"])
    encodedSize: float = OutputField(example_values=[1876966])
    ips: str = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    latency: float = OutputField(example_values=[0])
    percentage: float = OutputField(example_values=[59])
    size: float = OutputField(example_values=[1876925])
    type: str = OutputField(example_values=["Image"])


class ServerstatsOutput(ActionOutput):
    count: float = OutputField(example_values=[55])
    countries: str = OutputField(example_values=["IE"])
    encodedSize: float = OutputField(example_values=[2042170])
    ips: str = OutputField(example_values=["[2a00:1450:4001:825::200e]"])
    server: str = OutputField(example_values=["TestServer/1.4"])
    size: float = OutputField(example_values=[2410398])


class Tls1Output(ActionOutput):
    n2___ECDHE_ECDSA___AES_128_GCM: float = OutputField(
        example_values=[2], alias="2 / ECDHE_ECDSA / AES_128_GCM"
    )
    n2___ECDHE_RSA___AES_128_GCM: float = OutputField(
        example_values=[5], alias="2 / ECDHE_RSA / AES_128_GCM"
    )
    n3______AES_128_GCM: float = OutputField(
        example_values=[17], alias="3 /  / AES_128_GCM"
    )
    n3______AES_256_GCM: float = OutputField(
        example_values=[3], alias="3 /  / AES_256_GCM"
    )
    n2___ECDHE_RSA___CHACHA20_POLY1305: float = OutputField(
        example_values=[127], alias="2 / ECDHE_RSA / CHACHA20_POLY1305"
    )


class ProtocolsOutput(ActionOutput):
    QUIC______AES_128_GCM: float = OutputField(
        example_values=[9], alias="QUIC /  / AES_128_GCM"
    )
    TLS_1: Tls1Output


class TlsstatsOutput(ActionOutput):
    count: float = OutputField(example_values=[55])
    countries: str = OutputField(example_values=["IE"])
    encodedSize: float = OutputField(example_values=[2042170])
    ips: str = OutputField(example_values=["[2a03:2880:f11c:8183:face:b00c:0:25de]"])
    protocols: ProtocolsOutput
    securityState: str = OutputField(example_values=["neutral"])
    size: float = OutputField(example_values=[2410398])


class StatsOutput(ActionOutput):
    IPv6Percentage: float = OutputField(example_values=[75])
    adBlocked: float = OutputField(example_values=[2])
    domainStats: list[DomainstatsOutput]
    ipStats: list[IpstatsOutput]
    malicious: float = OutputField(example_values=[0])
    protocolStats: list[ProtocolstatsOutput]
    regDomainStats: list[RegdomainstatsOutput]
    resourceStats: list[ResourcestatsOutput]
    securePercentage: float = OutputField(example_values=[10])
    secureRequests: float = OutputField(example_values=[7])
    serverStats: list[ServerstatsOutput]
    tlsStats: list[TlsstatsOutput]
    totalLinks: float = OutputField(example_values=[4])
    uniqCountries: float = OutputField(example_values=[2])


class SubmitterOutput(ActionOutput):
    country: str = OutputField(example_values=["US"])


class TaskOutput(ActionOutput):
    domURL: str = OutputField(
        cef_types=["url"],
        example_values=["https://urlscan.io/dom/f04f2a29-d455-4830-874a-88191fb79352/"],
    )
    method: str = OutputField(example_values=["api"])
    options: OptionsOutput
    reportURL: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/result/f04f2a29-d455-4830-874a-88191fb79352/"
        ],
    )
    screenshotURL: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png"
        ],
    )
    source: str = OutputField(example_values=["4b0fb6d4"])
    time: str = OutputField(example_values=["2017-08-07T19:13:17.870Z"])
    url: str = OutputField(cef_types=["url"], example_values=["http://test.test"])
    userAgent: str = OutputField(example_values=["TestBrowser/7.0"])
    uuid: str = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"],
    )
    visibility: str = OutputField(example_values=["public"])
    domain: str = OutputField(example_values=["google.com"])
    apexDomain: str = OutputField(example_values=["google.com"])


class CommunityOutput(ActionOutput):
    score: float = OutputField(example_values=[0])
    votesBenign: float = OutputField(example_values=[0])
    votesMalicious: float = OutputField(example_values=[0])
    votesTotal: float = OutputField(example_values=[0])
    malicious: bool
    hasVerdicts: bool


class EnginesOutput(ActionOutput):
    benignTotal: float = OutputField(example_values=[0])
    enginesTotal: float = OutputField(example_values=[0])
    maliciousTotal: float = OutputField(example_values=[0])
    score: float = OutputField(example_values=[0])
    malicious: bool


class OverallOutput(ActionOutput):
    hasVerdicts: float = OutputField(example_values=[0])
    malicious: bool = OutputField(example_values=[False])
    score: float = OutputField(example_values=[0])


class UrlscanOutput(ActionOutput):
    malicious: bool = OutputField(example_values=[False])
    score: float = OutputField(example_values=[0])
    hasVerdicts: bool


class VerdictsOutput(ActionOutput):
    community: CommunityOutput
    engines: EnginesOutput
    overall: OverallOutput
    urlscan: UrlscanOutput


class ScannerOutput(ActionOutput):
    country: str = OutputField(example_values=["us"])


class DetonateUrlOutput(ActionOutput):
    api: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/api/v1/result/f04f2a29-d455-4830-874a-88191fb79352/"
        ],
    )
    data: DataOutput
    description: str = OutputField(
        example_values=[
            "The submitted domain is on our blacklist. For your own safety we did not perform this scan..."
        ]
    )
    fieldErrors: list[FielderrorsOutput]
    lists: ListsOutput
    message: str = OutputField(example_values=["Submission successful"])
    meta: MetaOutput
    options: OptionsOutput
    page: PageOutput
    result: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/result/f04f2a29-d455-4830-874a-88191fb79352/"
        ],
    )
    stats: StatsOutput
    status: float = OutputField(example_values=[400])
    submitter: SubmitterOutput
    task: TaskOutput
    url: str = OutputField(cef_types=["url"], example_values=["abc.test.test"])
    uuid: str = OutputField(example_values=["f04f2a29-d455-4830-874a-88191fb79352"])
    verdicts: VerdictsOutput
    visibility: str = OutputField(example_values=["public"])
    scanner: ScannerOutput


@app.action(
    description="Detonate a URL at urlscan.io",
    action_type="investigate",
    read_only=False,
    verbose="If the get_result parameter is set to true, then the action may take up to 2-3 minutes to execute because the action will poll for the results in the same call.",
    params_class=DetonateUrlParams,
    output_class=DetonateActionOutput,
    summary_type=AddedTagsSummary,
    view_handler=detonate_url_view_handler,
)
def detonate_url(params: DetonateUrlParams, soar: SOARClient, asset: Asset):
    return run_detonate_url(params, soar, asset)


class GetScreenshotParams(Params):
    report_id: str = Param(
        description="UUID of report", primary=True, cef_types=["urlscan submission id"]
    )
    container_id: float | None = Param(
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
