import ssl

import pytest

from pskcontext import Purpose, create_default_psk_context


def test_create_default_psk_context():
    context = create_default_psk_context(Purpose.CLIENT_AUTH, psk=b"")
    assert issubclass(type(context), ssl.SSLContext)
    assert context.protocol == ssl.PROTOCOL_TLS_CLIENT


def test_create_default_psk_context_unsupported_purpose():
    with pytest.raises(TypeError):
        # noinspection PyTypeChecker
        create_default_psk_context("123", psk=b"123")
