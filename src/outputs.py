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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput


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


class TaskOptionsOutput(PermissiveActionOutput):
    useragent: str | None = OutputField(example_values=["TestBrowser/7.0"])


class SimplePageOutput(PermissiveActionOutput):
    ip: str | None = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    asn: int | None = OutputField(example_values=[15169])
    asnname: str | None = OutputField(example_values=["GOOGLE"])
    city: str | None = OutputField(example_values=["Bursa"])
    country: str | None = OutputField(example_values=["TR"])
    domain: str | None = OutputField(cef_types=["domain"], example_values=["yahoo.com"])
    apexDomain: str | None = OutputField(example_values=["yahoo.com"])
    mimeType: str | None = OutputField(example_values=["text/html"])
    ptr: str | None = OutputField(example_values=["dns.google"])
    redirected: str | None = OutputField(example_values=["sub-domain"])
    server: str | None = OutputField(example_values=["nginx"])
    status: str | None = OutputField(example_values=["200"])
    title: str | None = OutputField(example_values=["Yahoo"])
    tlsAgeDays: int | None = OutputField(example_values=[28])
    tlsIssuer: str | None = OutputField(example_values=["WR2"])
    tlsValidDays: int | None = OutputField(example_values=[83])
    tlsValidFrom: str | None = OutputField(example_values=["2024-06-24T06:35:44.000Z"])
    umbrellaRank: int | None = OutputField(example_values=[10])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.yahoo.com"]
    )


class SimpleTaskOutput(PermissiveActionOutput):
    uuid: str | None = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"],
    )
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.yahoo.com"]
    )
    domURL: str | None = OutputField(
        cef_types=["url"], example_values=["http://test.test"]
    )
    domain: str | None = OutputField(example_values=["yahoo.com"])
    apexDomain: str | None = OutputField(example_values=["yahoo.com"])
    method: str | None = OutputField(example_values=["GET"])
    options: TaskOptionsOutput | None
    reportURL: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/result/f04f2a29-d455-4830-874a-88191fb79352/"
        ],
    )
    screenshotURL: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/screenshots/f04f2a29-d455-4830-874a-88191fb79352.png"
        ],
    )
    source: str | None = OutputField(example_values=["4b0fb6d4"])
    time: str | None = OutputField(example_values=["2017-08-07T19:13:17.870Z"])
    userAgent: str | None = OutputField(example_values=["TestBrowser/7.0"])
    visibility: str | None = OutputField(example_values=["public"])


class StatsGroupOutput(PermissiveActionOutput):
    count: int | None = OutputField(example_values=[1])
    countries: list[str] | None = OutputField(example_values=[["US"]])
    domain: str | None = OutputField(cef_types=["domain"], example_values=["yahoo.com"])
    domains: list[str] | None = OutputField(example_values=[["yahoo.com"]])
    encodedSize: int | None = OutputField(example_values=[1234])
    index: int | None = OutputField(example_values=[0])
    initiators: list[str] | None = OutputField(example_values=[["redirect"]])
    ip: str | None = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    ips: list[str] | None = OutputField(example_values=[["8.8.8.8"]])
    ipv6: bool | None
    latency: int | None = OutputField(example_values=[25])
    percentage: int | None = OutputField(example_values=[100])
    protocol: str | None = OutputField(example_values=["https"])
    redirects: int | None = OutputField(example_values=[0])
    regDomain: str | None = OutputField(example_values=["yahoo.com"])
    requests: int | None = OutputField(example_values=[1])
    securityState: str | None = OutputField(example_values=["secure"])
    server: str | None = OutputField(example_values=["nginx"])
    size: int | None = OutputField(example_values=[1234])
    type: str | None = OutputField(example_values=["Document"])


class SimpleStatsOutput(PermissiveActionOutput):
    requests: int | None = OutputField(example_values=[69])
    took: int | None = OutputField(example_values=[25])
    total: int | None = OutputField(example_values=[1])
    adBlocked: bool | None
    consoleMsgs: int | None = OutputField(example_values=[0])
    dataLength: int | None = OutputField(example_values=[1024])
    domainStats: list[StatsGroupOutput] | None
    encodedDataLength: int | None = OutputField(example_values=[1024])
    IPv6Percentage: int | None = OutputField(example_values=[0])
    ipStats: list[StatsGroupOutput] | None
    malicious: int | None = OutputField(example_values=[0])
    protocolStats: list[StatsGroupOutput] | None
    regDomainStats: list[StatsGroupOutput] | None
    resourceStats: list[StatsGroupOutput] | None
    securePercentage: int | None = OutputField(example_values=[100])
    secureRequests: int | None = OutputField(example_values=[20])
    serverStats: list[StatsGroupOutput] | None
    tlsStats: list[StatsGroupOutput] | None
    totalLinks: int | None = OutputField(example_values=[10])
    uniqCountries: int | None = OutputField(example_values=[1])
    uniqIPs: int | None = OutputField(example_values=[1])


class CertificateOutput(PermissiveActionOutput):
    issuer: str | None = OutputField(example_values=["WR2"])
    sanList: list[str] | None = OutputField(example_values=[["www.google.com"]])
    subjectName: str | None = OutputField(example_values=["www.google.com"])
    validFrom: int | None = OutputField(example_values=[1719210944])
    validTo: int | None = OutputField(example_values=[1726468544])


class ListsOutput(PermissiveActionOutput):
    asns: list[str] | None = OutputField(example_values=[["15169"]])
    certificates: list[CertificateOutput] | None
    countries: list[str] | None = OutputField(example_values=[["US"]])
    domains: list[str] | None = OutputField(example_values=[["google.com"]])
    hashes: list[str] | None = OutputField(
        example_values=[
            ["d41d8cd98f00b204e9800998ecf8427e"]  # pragma: allowlist secret
        ]
    )
    ips: list[str] | None = OutputField(example_values=[["8.8.8.8"]])
    linkDomains: list[str] | None = OutputField(example_values=[["google.com"]])
    servers: list[str] | None = OutputField(example_values=[["gws"]])
    urls: list[str] | None = OutputField(
        cef_types=["url"], example_values=[["https://www.google.com"]]
    )


class ConsoleMessageOutput(PermissiveActionOutput):
    column: int | None = OutputField(example_values=[1])
    level: str | None = OutputField(example_values=["info"])
    line: int | None = OutputField(example_values=[1])
    source: str | None = OutputField(example_values=["console-api"])
    text: str | None = OutputField(example_values=["message"])
    timestamp: int | None = OutputField(example_values=[1721648282157])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.google.com"]
    )


class ConsoleOutput(PermissiveActionOutput):
    message: ConsoleMessageOutput | None


class CookieOutput(PermissiveActionOutput):
    domain: str | None = OutputField(
        cef_types=["domain"], example_values=["google.com"]
    )
    expires: int | None = OutputField(example_values=[1721648282])
    httpOnly: bool | None
    name: str | None = OutputField(example_values=["session"])
    path: str | None = OutputField(example_values=["/"])
    priority: str | None = OutputField(example_values=["Medium"])
    sameParty: bool | None
    sameSite: str | None = OutputField(example_values=["Lax"])
    secure: bool | None
    session: bool | None
    size: int | None = OutputField(example_values=[64])
    sourcePort: int | None = OutputField(example_values=[443])
    sourceScheme: str | None = OutputField(example_values=["Secure"])
    value: str | None = OutputField(example_values=["cookie-value"])


class GlobalOutput(PermissiveActionOutput):
    prop: str | None = OutputField(example_values=["navigator"])
    type: str | None = OutputField(example_values=["object"])


class LinkOutput(PermissiveActionOutput):
    href: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.google.com"]
    )
    text: str | None = OutputField(example_values=["Google"])


class TimingOutput(PermissiveActionOutput):
    beginNavigation: int | None = OutputField(example_values=[1721648282000])
    domContentEventFired: int | None = OutputField(example_values=[1721648282000])
    frameNavigated: int | None = OutputField(example_values=[1721648282000])
    frameStartedLoading: int | None = OutputField(example_values=[1721648282000])
    frameStoppedLoading: int | None = OutputField(example_values=[1721648282000])
    loadEventFired: int | None = OutputField(example_values=[1721648282000])


class InitiatorInfoOutput(PermissiveActionOutput):
    host: str | None = OutputField(example_values=["www.google.com"])
    type: str | None = OutputField(example_values=["parser"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.google.com"]
    )


class RequestPayloadOutput(PermissiveActionOutput):
    hasPostData: bool | None
    initialPriority: str | None = OutputField(example_values=["VeryHigh"])
    method: str | None = OutputField(example_values=["GET"])
    mixedContentType: str | None = OutputField(example_values=["none"])
    postData: str | None = OutputField(example_values=[""])
    referrerPolicy: str | None = OutputField(
        example_values=["strict-origin-when-cross-origin"]
    )
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.google.com"]
    )


class SecurityDetailsOutput(PermissiveActionOutput):
    certificateId: int | None = OutputField(example_values=[0])
    certificateTransparencyCompliance: str | None = OutputField(
        example_values=["compliant"]
    )
    cipher: str | None = OutputField(example_values=["AES_128_GCM"])
    issuer: str | None = OutputField(example_values=["WR2"])
    keyExchange: str | None = OutputField(example_values=["ECDHE_RSA"])
    keyExchangeGroup: str | None = OutputField(example_values=["X25519"])
    protocol: str | None = OutputField(example_values=["TLS 1.3"])
    sanList: list[str] | None = OutputField(example_values=[["www.google.com"]])
    subjectName: str | None = OutputField(example_values=["www.google.com"])
    validFrom: int | None = OutputField(example_values=[1719210944])
    validTo: int | None = OutputField(example_values=[1726468544])


class ResponsePayloadOutput(PermissiveActionOutput):
    encodedDataLength: int | None = OutputField(example_values=[1024])
    fromPrefetchCache: bool | None
    mimeType: str | None = OutputField(example_values=["text/html"])
    protocol: str | None = OutputField(example_values=["h2"])
    remoteIPAddress: str | None = OutputField(
        cef_types=["ip", "ipv6"], example_values=["8.8.8.8"]
    )
    remotePort: int | None = OutputField(example_values=[443])
    responseTime: int | None = OutputField(example_values=[1721648282000])
    securityDetails: SecurityDetailsOutput | None
    securityState: str | None = OutputField(example_values=["secure"])
    status: int | None = OutputField(example_values=[200])
    statusText: str | None = OutputField(example_values=["OK"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.google.com"]
    )


class RequestEventOutput(PermissiveActionOutput):
    documentURL: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.google.com"]
    )
    frameId: str | None = OutputField(example_values=["frame"])
    hasUserGesture: bool | None
    initiator: InitiatorInfoOutput | None
    loaderId: str | None = OutputField(example_values=["loader"])
    primaryRequest: bool | None
    redirectResponse: ResponsePayloadOutput | None
    request: RequestPayloadOutput | None
    requestId: str | None = OutputField(example_values=["360549.24"])
    timestamp: int | None = OutputField(example_values=[1721648282])
    type: str | None = OutputField(example_values=["Document"])
    wallTime: int | None = OutputField(example_values=[1721648282])


class ResponseEventOutput(PermissiveActionOutput):
    size: int | None = OutputField(example_values=[1024])
    type: str | None = OutputField(example_values=["Document"])
    response: ResponsePayloadOutput | None


class RequestGroupOutput(PermissiveActionOutput):
    initiatorInfo: InitiatorInfoOutput | None
    request: RequestEventOutput | None
    requests: list[RequestEventOutput] | None
    response: ResponseEventOutput | None


class ProcessorDataOutput(PermissiveActionOutput):
    app: str | None = OutputField(example_values=["Bootstrap"])
    asn: int | None = OutputField(example_values=[15169])
    country: str | None = OutputField(example_values=["US"])
    date: str | None = OutputField(example_values=["2024-01-01"])
    description: str | None = OutputField(example_values=["GOOGLE"])
    hostname: str | None = OutputField(
        cef_types=["domain"], example_values=["www.google.com"]
    )
    icon: str | None = OutputField(example_values=["Bootstrap.png"])
    ip: str | None = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    name: str | None = OutputField(example_values=["GOOGLE"])
    ptr: str | None = OutputField(example_values=["dns.google"])
    rank: int | None = OutputField(example_values=[10])
    registrar: str | None = OutputField(example_values=["arin"])
    route: str | None = OutputField(example_values=["8.8.8.0/24"])
    source: str | None = OutputField(example_values=["abp"])
    type: str | None = OutputField(example_values=["Document"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.google.com"]
    )
    website: str | None = OutputField(
        cef_types=["url"], example_values=["https://getbootstrap.com"]
    )


class ProcessorOutput(PermissiveActionOutput):
    state: str | None = OutputField(example_values=["done"])
    data: list[ProcessorDataOutput] | None


class ProcessorsOutput(PermissiveActionOutput):
    abp: ProcessorOutput | None
    asn: ProcessorOutput | None
    cdnjs: ProcessorOutput | None
    done: ProcessorOutput | None
    geoip: ProcessorOutput | None
    gsb: ProcessorOutput | None
    rdns: ProcessorOutput | None
    umbrella: ProcessorOutput | None
    wappa: ProcessorOutput | None


class ReportMetaOutput(PermissiveActionOutput):
    processors: ProcessorsOutput | None


class ReportDataOutput(PermissiveActionOutput):
    console: list[ConsoleOutput] | None
    cookies: list[CookieOutput] | None
    globals: list[GlobalOutput] | None
    links: list[LinkOutput] | None
    requests: list[RequestGroupOutput] | None
    timing: TimingOutput | None


class ScannerOutput(PermissiveActionOutput):
    country: str | None = OutputField(example_values=["us"])


class SubmitterOutput(PermissiveActionOutput):
    country: str | None = OutputField(example_values=["us"])


class VerdictCommunityOutput(PermissiveActionOutput):
    hasVerdicts: bool | None
    malicious: bool | None
    score: int | None = OutputField(example_values=[0])
    votesBenign: int | None = OutputField(example_values=[0])
    votesMalicious: int | None = OutputField(example_values=[0])
    votesTotal: int | None = OutputField(example_values=[0])


class VerdictEnginesOutput(PermissiveActionOutput):
    benignTotal: int | None = OutputField(example_values=[0])
    enginesTotal: int | None = OutputField(example_values=[0])
    malicious: bool | None
    maliciousTotal: int | None = OutputField(example_values=[0])
    score: int | None = OutputField(example_values=[0])


class VerdictOverallOutput(PermissiveActionOutput):
    hasVerdicts: bool | None
    malicious: bool | None
    score: int | None = OutputField(example_values=[0])


class VerdictUrlscanOutput(PermissiveActionOutput):
    hasVerdicts: bool | None
    malicious: bool | None
    score: int | None = OutputField(example_values=[0])


class VerdictsOutput(PermissiveActionOutput):
    community: VerdictCommunityOutput | None
    engines: VerdictEnginesOutput | None
    overall: VerdictOverallOutput | None
    urlscan: VerdictUrlscanOutput | None


class SearchResultItemOutput(PermissiveActionOutput):
    result_id: str | None = OutputField(
        alias="_id", example_values=["86b7f70a-5039-419f-9aeb-8cba09404e92"]
    )
    indexedAt: str | None = OutputField(example_values=["2024-07-22T10:18:02.157Z"])
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
    sort: list[str] | None = OutputField(
        example_values=[
            [
                "2024-07-22T10:18:02.157Z",
                "86b7f70a-5039-419f-9aeb-8cba09404e92",
            ]
        ]
    )
    stats: SimpleStatsOutput | None
    uniq_countries: int | None = OutputField(example_values=[1])


class LookupActionOutput(PermissiveActionOutput):
    has_more: bool | None = OutputField(example_values=[False])
    results: list[SearchResultItemOutput] | None
    took: int | None = OutputField(example_values=[25])
    total: int | None = OutputField(example_values=[1])


class UrlscanReportOutput(PermissiveActionOutput):
    data: ReportDataOutput | None
    lists: ListsOutput | None
    meta: ReportMetaOutput | None
    page: SimplePageOutput | None
    scanner: ScannerOutput | None
    stats: SimpleStatsOutput | None
    submitter: SubmitterOutput | None
    task: SimpleTaskOutput | None
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.yahoo.com"]
    )
    uuid: str | None = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"],
    )
    verdicts: VerdictsOutput | None
    visibility: str | None = OutputField(example_values=["public"])


class DetonateActionOutput(UrlscanReportOutput):
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
