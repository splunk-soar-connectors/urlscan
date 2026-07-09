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


class HTTPHeadersOutput(PermissiveActionOutput):
    wildcard: str | None = OutputField(alias="*")
    Accept: str | None = OutputField()
    accept_ch: str | None = OutputField(alias="accept-ch")
    Accept_Ranges: str | None = OutputField(alias="Accept-Ranges")
    accept_ranges: str | None = OutputField(alias="accept-ranges")
    access_control_allow_credentials: str | None = OutputField(
        alias="access-control-allow-credentials"
    )
    Access_Control_Allow_Credentials: str | None = OutputField(
        alias="Access-Control-Allow-Credentials"
    )
    Access_Control_Allow_Headers: str | None = OutputField(
        alias="Access-Control-Allow-Headers"
    )
    access_control_allow_headers: str | None = OutputField(
        alias="access-control-allow-headers"
    )
    access_control_allow_method: str | None = OutputField(
        alias="access-control-allow-method"
    )
    Access_Control_Allow_Methods: str | None = OutputField(
        alias="Access-Control-Allow-Methods"
    )
    access_control_allow_methods: str | None = OutputField(
        alias="access-control-allow-methods"
    )
    access_control_allow_origin: str | None = OutputField(
        cef_types=["url"], alias="access-control-allow-origin"
    )
    Access_Control_Allow_Origin: str | None = OutputField(
        alias="Access-Control-Allow-Origin"
    )
    Access_Control_Expose_Headers: str | None = OutputField(
        alias="Access-Control-Expose-Headers"
    )
    access_control_expose_headers: str | None = OutputField(
        alias="access-control-expose-headers"
    )
    Access_Control_Max_Age: str | None = OutputField(alias="Access-Control-Max-Age")
    access_control_max_age: str | None = OutputField(alias="access-control-max-age")
    Access_Control_Request_Headers: str | None = OutputField(
        alias="Access-Control-Request-Headers"
    )
    Access_Control_Request_Method: str | None = OutputField(
        alias="Access-Control-Request-Method"
    )
    Age: str | None = OutputField()
    age: str | None = OutputField()
    allow: str | None = OutputField()
    alt_svc: str | None = OutputField(alias="alt-svc")
    Alt_Svc: str | None = OutputField(alias="Alt-Svc")
    apigw_requestid: str | None = OutputField(alias="apigw-requestid")
    ats_carp_promotion: str | None = OutputField(alias="ats-carp-promotion")
    cache_control: str | None = OutputField(alias="cache-control")
    Cache_Control: str | None = OutputField(alias="Cache-Control")
    cf_bgj: str | None = OutputField(alias="cf-bgj")
    cf_cache_status: str | None = OutputField(alias="cf-cache-status")
    cf_polished: str | None = OutputField(alias="cf-polished")
    cf_ray: str | None = OutputField(alias="cf-ray")
    Connection: str | None = OutputField()
    content_disposition: str | None = OutputField(alias="content-disposition")
    Content_Encoding: str | None = OutputField(alias="Content-Encoding")
    content_encoding: str | None = OutputField(alias="content-encoding")
    Content_Language: str | None = OutputField(alias="Content-Language")
    content_language: str | None = OutputField(alias="content-language")
    Content_Length: str | None = OutputField(alias="Content-Length")
    content_length: str | None = OutputField(alias="content-length")
    content_md5: str | None = OutputField(alias="content-md5")
    Content_Security_Policy: str | None = OutputField(alias="Content-Security-Policy")
    content_security_policy: str | None = OutputField(alias="content-security-policy")
    content_security_policy_report_only: str | None = OutputField(
        alias="content-security-policy-report-only"
    )
    Content_Security_Policy_Report_Only: str | None = OutputField(
        alias="Content-Security-Policy-Report-Only"
    )
    Content_Type: str | None = OutputField(alias="Content-Type")
    content_type: str | None = OutputField(alias="content-type")
    cross_origin_embedder_policy: str | None = OutputField(
        alias="cross-origin-embedder-policy"
    )
    cross_origin_opener_policy: str | None = OutputField(
        alias="cross-origin-opener-policy"
    )
    cross_origin_opener_policy_report_only: str | None = OutputField(
        alias="cross-origin-opener-policy-report-only"
    )
    cross_origin_resource_policy: str | None = OutputField(
        alias="cross-origin-resource-policy"
    )
    Date: str | None = OutputField()
    date: str | None = OutputField()
    debug: str | None = OutputField()
    display: str | None = OutputField()
    edge_control: str | None = OutputField(alias="edge-control")
    ETag: str | None = OutputField()
    Etag: str | None = OutputField()
    etag: str | None = OutputField()
    expect_ct: str | None = OutputField(alias="expect-ct")
    Expect_CT: str | None = OutputField(alias="Expect-CT")
    expires: str | None = OutputField()
    Expires: str | None = OutputField()
    google_creative_id: str | None = OutputField(alias="google-creative-id")
    google_lineitem_id: str | None = OutputField(alias="google-lineitem-id")
    google_mediationgroup_id: str | None = OutputField(alias="google-mediationgroup-id")
    google_mediationtag_id: str | None = OutputField(alias="google-mediationtag-id")
    Keep_Alive: str | None = OutputField(alias="Keep-Alive")
    Last_Modified: str | None = OutputField(alias="Last-Modified")
    last_modified: str | None = OutputField(alias="last-modified")
    link: str | None = OutputField()
    Location: str | None = OutputField(cef_types=["url"])
    location: str | None = OutputField(cef_types=["url"])
    nel: str | None = OutputField()
    Non_Authoritative_Reason: str | None = OutputField(alias="Non-Authoritative-Reason")
    observe_browsing_topics: str | None = OutputField(alias="observe-browsing-topics")
    Origin: str | None = OutputField(cef_types=["url"])
    p3p: str | None = OutputField()
    P3P: str | None = OutputField()
    permissions_policy: str | None = OutputField(alias="permissions-policy")
    Permissions_Policy: str | None = OutputField(alias="Permissions-Policy")
    pragma: str | None = OutputField()
    Pragma: str | None = OutputField()
    Public_Key_Pins_Report_Only: str | None = OutputField(
        alias="Public-Key-Pins-Report-Only"
    )
    public_key_pins_report_only: str | None = OutputField(
        alias="public-key-pins-report-only"
    )
    Referer: str | None = OutputField(cef_types=["url"])
    referrer_policy: str | None = OutputField(alias="referrer-policy")
    Referrer_Policy: str | None = OutputField(alias="Referrer-Policy")
    report_to: str | None = OutputField(alias="report-to")
    Sec_Fetch_Mode: str | None = OutputField(alias="Sec-Fetch-Mode")
    Server: str | None = OutputField()
    server: str | None = OutputField()
    server_processing_duration_in_ticks: str | None = OutputField(
        alias="server-processing-duration-in-ticks"
    )
    server_timing: str | None = OutputField(alias="server-timing")
    set_cookie: str | None = OutputField(alias="set-cookie")
    Set_Cookie: str | None = OutputField(alias="Set-Cookie")
    status: str | None = OutputField()
    Strict_Transport_Security: str | None = OutputField(
        alias="Strict-Transport-Security"
    )
    strict_transport_security: str | None = OutputField(
        alias="strict-transport-security"
    )
    timing_allow_origin: str | None = OutputField(alias="timing-allow-origin")
    Timing_Allow_Origin: str | None = OutputField(alias="Timing-Allow-Origin")
    Transfer_Encoding: str | None = OutputField(alias="Transfer-Encoding")
    Upgrade: str | None = OutputField()
    Upgrade_Insecure_Requests: str | None = OutputField(
        alias="Upgrade-Insecure-Requests"
    )
    User_Agent: str | None = OutputField(alias="User-Agent")
    vary: str | None = OutputField()
    Vary: str | None = OutputField()
    version: str | None = OutputField()
    Via: str | None = OutputField()
    via: str | None = OutputField()
    X_Amz_Cf_Id: str | None = OutputField(alias="X-Amz-Cf-Id")
    x_amz_cf_id: str | None = OutputField(alias="x-amz-cf-id")
    X_Amz_Cf_Pop: str | None = OutputField(alias="X-Amz-Cf-Pop")
    x_amz_cf_pop: str | None = OutputField(alias="x-amz-cf-pop")
    x_amz_id_2: str | None = OutputField(alias="x-amz-id-2")
    x_amz_request_id: str | None = OutputField(alias="x-amz-request-id")
    x_amz_server_side_encryption: str | None = OutputField(
        alias="x-amz-server-side-encryption"
    )
    x_amz_version_id: str | None = OutputField(alias="x-amz-version-id")
    X_Cache: str | None = OutputField(alias="X-Cache")
    x_cache: str | None = OutputField(alias="x-cache")
    x_cache_status: str | None = OutputField(alias="x-cache-status")
    x_content_type_options: str | None = OutputField(alias="x-content-type-options")
    X_Content_Type_Options: str | None = OutputField(alias="X-Content-Type-Options")
    X_DIS_Request_ID: str | None = OutputField(alias="X-DIS-Request-ID")
    x_envoy_upstream_service_time: str | None = OutputField(
        alias="x-envoy-upstream-service-time"
    )
    x_fb_content_md5: str | None = OutputField(
        cef_types=["md5"], alias="x-fb-content-md5"
    )
    x_fb_debug: str | None = OutputField(alias="x-fb-debug")
    x_frame_options: str | None = OutputField(alias="x-frame-options")
    X_Frame_Options: str | None = OutputField(alias="X-Frame-Options")
    X_Goog_Api_Key: str | None = OutputField(alias="X-Goog-Api-Key")
    x_goog_generation: str | None = OutputField(alias="x-goog-generation")
    x_goog_hash: str | None = OutputField(alias="x-goog-hash")
    x_goog_metageneration: str | None = OutputField(alias="x-goog-metageneration")
    x_goog_storage_class: str | None = OutputField(alias="x-goog-storage-class")
    x_goog_stored_content_encoding: str | None = OutputField(
        alias="x-goog-stored-content-encoding"
    )
    x_goog_stored_content_length: str | None = OutputField(
        alias="x-goog-stored-content-length"
    )
    x_guploader_uploadid: str | None = OutputField(alias="x-guploader-uploadid")
    X_LLID: str | None = OutputField(cef_types=["md5"], alias="X-LLID")
    x_middleton_display: str | None = OutputField(alias="x-middleton-display")
    x_mnet_hl2: str | None = OutputField(alias="x-mnet-hl2")
    x_nbr: str | None = OutputField(alias="x-nbr")
    X_PINGBACK: str | None = OutputField(alias="X-PINGBACK")
    X_Powered_By: str | None = OutputField(alias="X-Powered-By")
    x_rgw_object_type: str | None = OutputField(alias="x-rgw-object-type")
    X_Robots_Tag: str | None = OutputField(alias="X-Robots-Tag")
    x_robots_tag: str | None = OutputField(alias="x-robots-tag")
    X_Same_Domain: str | None = OutputField(cef_types=["domain"], alias="X-Same-Domain")
    x_server: str | None = OutputField(alias="x-server")
    x_sol: str | None = OutputField(alias="x-sol")
    x_ua_compatible: str | None = OutputField(alias="x-ua-compatible")
    X_User_Agent: str | None = OutputField(alias="X-User-Agent")
    x_xss_protection: str | None = OutputField(alias="x-xss-protection")
    X_XSS_Protection: str | None = OutputField(alias="X-XSS-Protection")


class HTTPRequestHeadersOutput(PermissiveActionOutput):
    wildcard: str | None = OutputField(alias="*")
    authority: str | None = OutputField(alias=":authority")
    method: str | None = OutputField(alias=":method")
    path: str | None = OutputField(alias=":path")
    scheme: str | None = OutputField(cef_types=["url"], alias=":scheme")
    Accept: str | None = OutputField()
    accept: str | None = OutputField()
    Accept_Encoding: str | None = OutputField(alias="Accept-Encoding")
    accept_encoding: str | None = OutputField(alias="accept-encoding")
    Accept_Language: str | None = OutputField(alias="Accept-Language")
    accept_language: str | None = OutputField(alias="accept-language")
    Cache_Control: str | None = OutputField(alias="Cache-Control")
    cache_control: str | None = OutputField(alias="cache-control")
    Connection: str | None = OutputField()
    content_length: str | None = OutputField(alias="content-length")
    content_type: str | None = OutputField(alias="content-type")
    Cookie: str | None = OutputField()
    cookie: str | None = OutputField()
    Host: str | None = OutputField()
    origin: str | None = OutputField(cef_types=["url"])
    Pragma: str | None = OutputField()
    pragma: str | None = OutputField()
    Referer: str | None = OutputField()
    referer: str | None = OutputField(cef_types=["url"])
    Sec_Fetch_Dest: str | None = OutputField(alias="Sec-Fetch-Dest")
    sec_fetch_dest: str | None = OutputField(alias="sec-fetch-dest")
    Sec_Fetch_Mode: str | None = OutputField(alias="Sec-Fetch-Mode")
    sec_fetch_mode: str | None = OutputField(alias="sec-fetch-mode")
    Sec_Fetch_Site: str | None = OutputField(alias="Sec-Fetch-Site")
    sec_fetch_site: str | None = OutputField(alias="sec-fetch-site")
    Sec_Fetch_User: str | None = OutputField(alias="Sec-Fetch-User")
    sec_fetch_user: str | None = OutputField(alias="sec-fetch-user")
    Upgrade_Insecure_Requests: str | None = OutputField(
        alias="Upgrade-Insecure-Requests"
    )
    upgrade_insecure_requests: str | None = OutputField(
        alias="upgrade-insecure-requests"
    )
    User_Agent: str | None = OutputField(alias="User-Agent")
    user_agent: str | None = OutputField(alias="user-agent")
    x_same_domain: str | None = OutputField(cef_types=["domain"], alias="x-same-domain")


class ResponseTimingOutput(PermissiveActionOutput):
    connectEnd: float | None = OutputField()
    connectStart: float | None = OutputField()
    dnsEnd: float | None = OutputField()
    dnsStart: float | None = OutputField()
    proxyEnd: float | None = OutputField()
    proxyStart: float | None = OutputField()
    pushEnd: float | None = OutputField()
    pushStart: float | None = OutputField()
    receiveHeadersEnd: float | None = OutputField()
    receiveHeadersStart: float | None = OutputField()
    requestTime: float | None = OutputField()
    sendEnd: float | None = OutputField()
    sendStart: float | None = OutputField()
    sslEnd: float | None = OutputField()
    sslStart: float | None = OutputField()
    workerFetchStart: float | None = OutputField()
    workerReady: float | None = OutputField()
    workerRespondWithSettled: float | None = OutputField()
    workerStart: float | None = OutputField()


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


class SubDomainOutput(PermissiveActionOutput):
    country: str | None = OutputField(example_values=["IE"])
    domain: str | None = OutputField(
        cef_types=["domain"], example_values=["example.com"]
    )
    failed: bool | None


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
    subDomains: list[SubDomainOutput] | None
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


class CallFrameOutput(PermissiveActionOutput):
    columnNumber: float | None = OutputField(example_values=[386])
    functionName: str | None = OutputField(example_values=["lb"])
    lineNumber: float | None = OutputField(example_values=[13])
    scriptId: str | None = OutputField(example_values=["40"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.google.com"]
    )


class InitiatorStackOutput(PermissiveActionOutput):
    callFrames: list[CallFrameOutput] | None


class InitiatorInfoOutput(PermissiveActionOutput):
    columnNumber: float | None = OutputField(example_values=[88])
    host: str | None = OutputField(example_values=["www.google.com"])
    lineNumber: float | None = OutputField(example_values=[27])
    requestId: str | None = OutputField(example_values=["360549.24"])
    stack: InitiatorStackOutput | None
    type: str | None = OutputField(example_values=["parser"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.google.com"]
    )


class PostDataEntryOutput(PermissiveActionOutput):
    bytes: str | None = OutputField(example_values=["payload"])


class RequestPayloadOutput(PermissiveActionOutput):
    headers: HTTPHeadersOutput | None
    hasPostData: bool | None
    initialPriority: str | None = OutputField(example_values=["VeryHigh"])
    isLinkPreload: bool | None
    isSameSite: bool | None
    method: str | None = OutputField(example_values=["GET"])
    mixedContentType: str | None = OutputField(example_values=["none"])
    postData: str | None = OutputField(example_values=[""])
    postDataEntries: list[PostDataEntryOutput] | None
    referrerPolicy: str | None = OutputField(
        example_values=["strict-origin-when-cross-origin"]
    )
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://www.google.com"]
    )
    urlFragment: str | None = OutputField(example_values=["fragment"])


class SignedCertificateTimestampOutput(PermissiveActionOutput):
    hashAlgorithm: str | None = OutputField(example_values=["SHA-256"])
    logDescription: str | None = OutputField(
        example_values=["Google 'Xenon2024h1' log"]
    )
    logId: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "0000000000000000000000000000000000000000000000000000000000000000"
        ],
    )
    origin: str | None = OutputField(example_values=["Embedded in certificate"])
    signatureAlgorithm: str | None = OutputField(example_values=["ECDSA"])
    signatureData: str | None = OutputField(example_values=["3045022100"])
    status: str | None = OutputField(example_values=["Verified"])
    timestamp: int | None = OutputField(example_values=[1719210944000])


class SecurityDetailsOutput(PermissiveActionOutput):
    certificateId: int | None = OutputField(example_values=[0])
    certificateTransparencyCompliance: str | None = OutputField(
        example_values=["compliant"]
    )
    cipher: str | None = OutputField(example_values=["AES_128_GCM"])
    encryptedClientHello: bool | None
    issuer: str | None = OutputField(example_values=["WR2"])
    keyExchange: str | None = OutputField(example_values=["ECDHE_RSA"])
    keyExchangeGroup: str | None = OutputField(example_values=["X25519"])
    protocol: str | None = OutputField(example_values=["TLS 1.3"])
    sanList: list[str] | None = OutputField(example_values=[["www.google.com"]])
    serverSignatureAlgorithm: int | None = OutputField(example_values=[1027])
    signedCertificateTimestampList: list[SignedCertificateTimestampOutput] | None
    subjectName: str | None = OutputField(example_values=["www.google.com"])
    validFrom: int | None = OutputField(example_values=[1719210944])
    validTo: int | None = OutputField(example_values=[1726468544])


class SecurityHeaderOutput(PermissiveActionOutput):
    name: str | None = OutputField(example_values=["x-frame-options"])
    value: str | None = OutputField(example_values=["SAMEORIGIN"])


class ResponsePayloadOutput(PermissiveActionOutput):
    alternateProtocolUsage: str | None = OutputField(
        example_values=["unspecifiedReason"]
    )
    asn: AsnOutput | None
    charset: str | None = OutputField(example_values=["utf-8"])
    encodedDataLength: int | None = OutputField(example_values=[1024])
    fromDiskCache: bool | None
    fromPrefetchCache: bool | None
    fromServiceWorker: bool | None
    geoip: GeoIpOutput | None
    headers: HTTPHeadersOutput | None
    headersText: str | None = OutputField(example_values=["HTTP/1.1 200 OK"])
    mimeType: str | None = OutputField(example_values=["text/html"])
    protocol: str | None = OutputField(example_values=["h2"])
    rdns: RdnsOutput | None
    remoteIPAddress: str | None = OutputField(
        cef_types=["ip", "ipv6"], example_values=["8.8.8.8"]
    )
    remotePort: int | None = OutputField(example_values=[443])
    requestHeaders: HTTPRequestHeadersOutput | None
    requestHeadersText: str | None = OutputField(example_values=["GET / HTTP/1.1"])
    responseTime: int | None = OutputField(example_values=[1721648282000])
    securityDetails: SecurityDetailsOutput | None
    securityHeaders: list[SecurityHeaderOutput] | None
    securityState: str | None = OutputField(example_values=["secure"])
    serviceWorkerResponseSource: str | None = OutputField(example_values=["network"])
    status: int | None = OutputField(example_values=[200])
    statusText: str | None = OutputField(example_values=["OK"])
    timing: ResponseTimingOutput | None
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
    redirectHasExtraInfo: bool | None
    redirectResponse: ResponsePayloadOutput | None
    request: RequestPayloadOutput | None
    requestId: str | None = OutputField(example_values=["360549.24"])
    timestamp: int | None = OutputField(example_values=[1721648282])
    type: str | None = OutputField(example_values=["Document"])
    wallTime: int | None = OutputField(example_values=[1721648282])


class CorsErrorStatusOutput(PermissiveActionOutput):
    corsError: str | None = OutputField(example_values=["MissingAllowOriginHeader"])
    failedParameter: str | None = OutputField(example_values=[""])


class FailedRequestOutput(PermissiveActionOutput):
    blockedReason: str | None = OutputField(example_values=["mixed-content"])
    canceled: bool | None
    corsErrorStatus: CorsErrorStatusOutput | None
    errorText: str | None = OutputField(example_values=["net::ERR_FAILED"])
    requestId: str | None = OutputField(example_values=["24696.156"])
    timestamp: float | None = OutputField(example_values=[25061896.916161])
    type: str | None = OutputField(example_values=["Document"])


class SourceMatchOutput(PermissiveActionOutput):
    file: str | None = OutputField(example_values=["jquery.js"])
    project: str | None = OutputField(example_values=["jquery"])
    project_url: str | None = OutputField(
        cef_types=["url"], example_values=["https://example.com/project"]
    )
    source: str | None = OutputField(example_values=["cdnjs"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://example.com/file.js"]
    )


class ResponseAbpOutput(PermissiveActionOutput):
    source: str | None = OutputField(example_values=["abp"])
    type: str | None = OutputField(example_values=["Document"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://example.com"]
    )


class ResponseEventOutput(PermissiveActionOutput):
    abp: ResponseAbpOutput | None
    asn: AsnOutput | None
    dataLength: int | None = OutputField(example_values=[1024])
    encodedDataLength: int | None = OutputField(example_values=[1024])
    failed: FailedRequestOutput | None
    geoip: GeoIpOutput | None
    hash: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "0000000000000000000000000000000000000000000000000000000000000000"
        ],
    )
    hashmatches: list[SourceMatchOutput] | None
    hasExtraInfo: bool | None
    rdns: RdnsOutput | None
    requestId: str | None = OutputField(example_values=["24696.156"])
    size: int | None = OutputField(example_values=[1024])
    type: str | None = OutputField(example_values=["Document"])
    response: ResponsePayloadOutput | None


class RequestGroupOutput(PermissiveActionOutput):
    initiatorInfo: InitiatorInfoOutput | None
    request: RequestEventOutput | None
    requests: list[RequestEventOutput] | None
    response: ResponseEventOutput | None


class ProcessorCategoryOutput(PermissiveActionOutput):
    name: str | None = OutputField(example_values=["Web Frameworks"])
    priority: float | None = OutputField(example_values=[7])


class ProcessorConfidenceOutput(PermissiveActionOutput):
    confidence: float | None = OutputField(example_values=[100])
    pattern: str | None = OutputField(example_values=["bootstrap"])


class ProcessorThreatOutput(PermissiveActionOutput):
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://example.com"]
    )


class ProcessorMatchOutput(PermissiveActionOutput):
    cacheDuration: str | None = OutputField(example_values=["300s"])
    file: str | None = OutputField(example_values=["jquery.js"])
    platformType: str | None = OutputField(example_values=["ANY_PLATFORM"])
    project: str | None = OutputField(example_values=["jquery"])
    project_url: str | None = OutputField(
        cef_types=["url"], example_values=["https://example.com/project"]
    )
    source: str | None = OutputField(example_values=["cdnjs"])
    threat: ProcessorThreatOutput | None
    threatEntryType: str | None = OutputField(example_values=["URL"])
    threatType: str | None = OutputField(example_values=["MALWARE"])
    url: str | None = OutputField(
        cef_types=["url"], example_values=["https://example.com/file.js"]
    )


class ProcessorDataOutput(PermissiveActionOutput):
    app: str | None = OutputField(example_values=["Bootstrap"])
    asn: str | None = OutputField(example_values=["AS15169"])
    categories: list[ProcessorCategoryOutput] | None
    confidence: list[ProcessorConfidenceOutput] | None
    confidenceTotal: float | None = OutputField(example_values=[100])
    country: str | None = OutputField(example_values=["US"])
    date: str | None = OutputField(example_values=["2024-01-01"])
    description: str | None = OutputField(example_values=["GOOGLE"])
    geoip: GeoIpOutput | None
    hash: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "0000000000000000000000000000000000000000000000000000000000000000"
        ],
    )
    hostname: str | None = OutputField(
        cef_types=["domain"], example_values=["www.google.com"]
    )
    icon: str | None = OutputField(example_values=["Bootstrap.png"])
    ip: str | None = OutputField(cef_types=["ip", "ipv6"], example_values=["8.8.8.8"])
    matches: list[ProcessorMatchOutput] | None
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


class SingleProcessorOutput(PermissiveActionOutput):
    state: str | None = OutputField(example_values=["done"])
    data: ProcessorDataOutput | None


class DoneProcessorDataOutput(PermissiveActionOutput):
    state: str | None = OutputField(example_values=["done"])


class DoneProcessorOutput(PermissiveActionOutput):
    state: str | None = OutputField(example_values=["done"])
    data: DoneProcessorDataOutput | None


class ProcessorsOutput(PermissiveActionOutput):
    abp: ProcessorOutput | None
    asn: ProcessorOutput | None
    cdnjs: ProcessorOutput | None
    done: DoneProcessorOutput | None
    geoip: ProcessorOutput | None
    gsb: SingleProcessorOutput | None
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
