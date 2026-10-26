from unittest.mock import MagicMock

from src.tp3.utils.captcha import Captcha


def test_captcha_init():
    # Given
    url = "http://example.com/captcha"

    # When
    captcha = Captcha(MagicMock(), url)

    # Then
    assert captcha.url == url
    assert captcha.image == ""
    assert captcha.value == ""


def test_solve(monkeypatch):
    # Given
    monkeypatch.setattr(
        "src.tp3.utils.captcha.pytesseract.image_to_string",
        lambda img, config=None: "ABC12\n",
    )
    captcha = Captcha(MagicMock(), "http://example.com/captcha")
    captcha.image = "fake"

    # When
    captcha.solve()

    # Then
    assert captcha.get_value() == "ABC12"


def test_get_value():
    # Given
    captcha = Captcha(MagicMock(), "http://example.com/captcha")
    captcha.value = "TEST123"

    # When
    result = captcha.get_value()

    # Then
    assert result == "TEST123"
