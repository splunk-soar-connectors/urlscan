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
    report_uuid: str | None = OutputField(
        cef_types=["urlscan submission id"],
        example_values=["f04f2a29-d455-4830-874a-88191fb79352"],
    )
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
    asn: str | None = OutputField(example_values=["AS15169"])
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


class AsnOutput(PermissiveActionOutput):
    asn: str | None = OutputField(example_values=["43260"])
    country: str | None = OutputField(example_values=["TR"])
    date: str | None = OutputField(example_values=["2007-07-04"])
    description: str | None = OutputField(example_values=["DGN, TR"])
    ip: str | None = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    name: str | None = OutputField(example_values=["DGN"])
    registrar: str | None = OutputField(example_values=["ripencc"])
    route: str | None = OutputField(example_values=["2a00:1288:110::/46"])


class GeoIpOutput(PermissiveActionOutput):
    area: float | None = OutputField(example_values=[100])
    city: str | None = OutputField(example_values=["Bursa"])
    country: str | None = OutputField(example_values=["TR"])
    country_name: str | None = OutputField(example_values=["Turkey"])
    eu: str | None = OutputField(example_values=["0"])
    ll: float | None = OutputField(example_values=[-8])
    metro: float | None = OutputField(example_values=[0])
    range: float | None = OutputField(example_values=[1167286271])
    region: str | None = OutputField(example_values=["16"])
    timezone: str | None = OutputField(example_values=["Europe/London"])
    zip: float | None = OutputField(example_values=[16245])


class RdnsOutput(PermissiveActionOutput):
    ip: str | None = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    ptr: str | None = OutputField(example_values=["dns.google"])


class TlsProtocolsOutput(PermissiveActionOutput):
    wildcard: float | None = OutputField(alias="*")
    quic_none_aes_128_gcm: float | None = OutputField(alias="QUIC /  / AES_128_GCM")
    tls_1_2_ecdhe_ecdsa_aes_128_gcm: float | None = OutputField(
        alias="TLS 1.2 / ECDHE_ECDSA / AES_128_GCM"
    )
    tls_1_2_ecdhe_rsa_chacha20_poly1305: float | None = OutputField(
        alias="TLS 1.2 / ECDHE_RSA / CHACHA20_POLY1305"
    )
    tls_1_2_ecdhe_rsa_aes_128_gcm: float | None = OutputField(
        alias="TLS 1.2 / ECDHE_RSA / AES_128_GCM"
    )
    tls_1_3_none_aes_128_gcm: float | None = OutputField(
        alias="TLS 1.3 / NONE / AES_128_GCM"
    )
    tls_1_3_empty_aes_128_gcm: float | None = OutputField(
        alias="TLS 1.3 /  / AES_128_GCM"
    )
    tls_1_3_empty_aes_256_gcm: float | None = OutputField(
        alias="TLS 1.3 /  / AES_256_GCM"
    )


class StatsGroupOutput(PermissiveActionOutput):
    asn: AsnOutput | None
    compression: str | None = OutputField(example_values=["gzip"])
    count: int | None = OutputField(example_values=[1])
    countries: list[str] | None = OutputField(example_values=[["US"]])
    domain: str | None = OutputField(cef_types=["domain"], example_values=["yahoo.com"])
    domains: list[str] | None = OutputField(example_values=[["yahoo.com"]])
    encodedSize: int | None = OutputField(example_values=[1234])
    geoip: GeoIpOutput | None
    index: int | None = OutputField(example_values=[0])
    initiators: list[str] | None = OutputField(example_values=[["redirect"]])
    ip: str | None = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    ips: list[str] | None = OutputField(
        cef_types=["ip", "ipv6"], example_values=[["8.8.8.8"]]
    )
    ipv6: bool | None
    latency: int | None = OutputField(example_values=[25])
    percentage: int | None = OutputField(example_values=[100])
    protocol: str | None = OutputField(example_values=["https"])
    protocols: TlsProtocolsOutput | None
    rdns: RdnsOutput | None
    redirects: int | None = OutputField(example_values=[0])
    regDomain: str | None = OutputField(
        cef_types=["domain"], example_values=["yahoo.com"]
    )
    requests: int | None = OutputField(example_values=[1])
    securityState: str | None = OutputField(example_values=["secure"])
    server: str | None = OutputField(example_values=["nginx"])
    size: int | None = OutputField(example_values=[1234])
    type: str | None = OutputField(example_values=["Document"])


class SimpleStatsOutput(PermissiveActionOutput):
    requests: int | None = OutputField(example_values=[69])
    took: int | None = OutputField(example_values=[25])
    total: int | None = OutputField(example_values=[1])
    adBlocked: int | None = OutputField(example_values=[2])
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
        cef_types=["sha256"],
        example_values=[
            ["d41d8cd98f00b204e9800998ecf8427e"]  # pragma: allowlist secret
        ],
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
    partitionKey: str | None = OutputField(example_values=["https://example.com"])
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
    beginNavigation: str | None = OutputField(
        example_values=["2024-07-22T10:18:02.157Z"]
    )
    domContentEventFired: str | None = OutputField(
        example_values=["2024-07-22T10:18:02.157Z"]
    )
    frameNavigated: str | None = OutputField(
        example_values=["2024-07-22T10:18:02.157Z"]
    )
    frameStartedLoading: str | None = OutputField(
        example_values=["2024-07-22T10:18:02.157Z"]
    )
    frameStoppedLoading: str | None = OutputField(
        example_values=["2024-07-22T10:18:02.157Z"]
    )
    loadEventFired: str | None = OutputField(
        example_values=["2024-07-22T10:18:02.157Z"]
    )


class ReportMetaOutput(PermissiveActionOutput):
    processors: PermissiveActionOutput | None


class ReportDataOutput(PermissiveActionOutput):
    console: list[ConsoleOutput] | None
    cookies: list[CookieOutput] | None
    globals: list[GlobalOutput] | None
    links: list[LinkOutput] | None
    requests: list[PermissiveActionOutput] | None
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


class FieldErrorOutput(PermissiveActionOutput):
    location: str | None = OutputField(example_values=["body"])
    msg: str | None = OutputField(
        example_values=["must be between 5 and 2083 characters"]
    )
    param: str | None = OutputField(example_values=["url"])
    value: str | None = OutputField(example_values=["123"])


class DetonateActionOutput(UrlscanReportOutput):
    api: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/api/v1/result/f04f2a29-d455-4830-874a-88191fb79352/"
        ],
    )
    message: str | None = OutputField(example_values=["Submission successful"])
    description: str | None = OutputField(
        example_values=["The submitted URL was blocked from scanning."]
    )
    fieldErrors: list[FieldErrorOutput] | None
    options: TaskOptionsOutput | None
    result: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://urlscan.io/api/v1/result/f04f2a29-d455-4830-874a-88191fb79352"
        ],
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
