import base64
from unittest.mock import MagicMock

from src.tp3.utils.session import Session


def test_session_init():
    # Given
    url = "http://example.com/captcha"

    # When
    session = Session(url)

    # Then
    assert session.url == url
    assert session.captcha_value == ""
    assert session.flag_value == ""
    assert session.valid_flag == ""
    assert session.session is not None
    assert session.host == ""
    assert session.port == 0
    assert session.key == b""
    assert session.tokenToXor == b""


def test_submit_request(monkeypatch):
    # Given
    session = Session("http://example.com/captcha")
    session.host = "host"
    session.port = 1
    session.key = b'\xff\x19;"'

    srv_response = MagicMock()
    srv_response.recvline.side_effect = [
        base64.b64encode(b"\x9d)_\x1b\xc9!\t\x1a\x9d \x0fD\x9e{^\x1a"),
        base64.b64encode(b"\x9a/Y\x11\xca{\x08\x15\x9c _\x11\x9d/\n@"),
        base64.b64encode(b"\xc9(\x03\x11\x9e-Z\x10\xc8*\x0f\x17\xc8)_\x12"),
        b"OK ESGI{chain_dev-local-flag}",
    ]
    monkeypatch.setattr("src.tp3.utils.session.remote", lambda host, port: srv_response)

    # When
    session.submit_request()

    # Then
    assert session.get_flag() == "ESGI{chain_dev-local-flag}"


def test_process_response():
    # Given
    session = Session("http://example.com/captcha")
    session.tokenToXor = b"\x9d)_\x1b\xc9!\t\x1a\x9d \x0fD\x9e{^\x1a"
    session.key = b'\xff\x19;"'

    # When
    result = session._process_response()

    # Then
    # This is a minimal test since the method doesn't do anything yet
    assert result == "b0d96828b94fabe8"


# Need to fake captha to test prepare_request
class FakeCaptcha:
    def __init__(self, session, url):
        pass

    def capture(self):
        pass

    def solve(self):
        pass

    def get_value(self):
        return "ABC12"


def test_prepare_request(monkeypatch):
    # Given
    monkeypatch.setattr("src.tp3.utils.session.Captcha", FakeCaptcha)
    session = Session("http://example.com/captcha")
    session.session = MagicMock()
    session.session.post.return_value.json.return_value = {
        "flag1": "ESGI{web_dev-local-flag}",
        "host": "127.0.0.1",
        "port": 9090,
        "key": "ff193b22",
    }

    # When
    result = session.prepare_request()

    # Then
    assert result == "ESGI{web_dev-local-flag}"
    assert session.host == "127.0.0.1"
    assert session.port == 9090
    assert session.key == bytes.fromhex("ff193b22")


def test_get_flag():
    # Given
    session = Session("http://example.com/captcha")
    session.valid_flag = "ESGI{chain_dev-local-flag}"

    # When
    result = session.get_flag()

    # Then
    assert result == "ESGI{chain_dev-local-flag}"
