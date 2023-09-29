import socket
import ssl

from pskcontext import Purpose, create_default_psk_context


def test_create_default_psk_context():
    context = create_default_psk_context(Purpose.CLIENT_AUTH, psk=b"")
    assert issubclass(type(context), ssl.SSLContext)
    assert context.protocol == ssl.PROTOCOL_TLS_CLIENT


def test_ssl_object():
    psk = b"psk-key"
    context = create_default_psk_context(Purpose.CLIENT_AUTH, psk=psk)

    ssl_object = context.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO())

    assert getattr(ssl_object, "psk") == psk


def test_ssl_socket():
    psk = b"psk-key"
    context = create_default_psk_context(Purpose.CLIENT_AUTH, psk=psk)
    context.check_hostname = False

    with socket.socket(socket.AF_INET) as s:
        ssl_socket = context.wrap_socket(s, server_side=False)

    assert getattr(ssl_socket, "psk") == psk
