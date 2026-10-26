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


def test_submit_request():
    # Given
    session = Session("http://example.com/captcha")

    # When
    session.submit_request()

    # Then
    # This is a minimal test since the method doesn't do anything yet
    assert True


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


def test_get_flag():
    # Given
    session = Session("http://example.com/captcha")
    session.valid_flag = "FLAG123"

    # When
    result = session.get_flag()

    # Then
    assert result == "FLAG123"
