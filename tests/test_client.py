from types import SimpleNamespace

from src.client import UrlscanClient


def test_client_defaults_to_tls_verification_for_assets_without_the_field():
    client = UrlscanClient.from_asset(SimpleNamespace(api_key=None, timeout=None))
    assert client.verify_server_cert is True

    opt_out = UrlscanClient.from_asset(
        SimpleNamespace(api_key=None, timeout=None, verify_server_cert=False)
    )
    assert opt_out.verify_server_cert is False
