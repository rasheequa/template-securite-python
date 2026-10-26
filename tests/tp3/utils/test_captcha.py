import io
from unittest.mock import MagicMock

from PIL import Image as PILImage

from src.tp3.utils.captcha import Captcha


def _png_bytes():
    buf = io.BytesIO()
    PILImage.new("RGB", (4, 4), "white").save(buf, format="PNG")
    return buf.getvalue()


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


def test_capture():
    # Given
    session = MagicMock()
    page = MagicMock(text='<img src="/captcha.png" alt="captcha">')
    image = MagicMock(content=_png_bytes())
    session.get.side_effect = [page, image]
    captcha = Captcha(session, "http://example.com")

    # When
    captcha.capture()

    # Then
    assert captcha.image.mode == "L"
    session.get.assert_any_call("http://example.com/captcha.png")


def test_get_value():
    # Given
    captcha = Captcha(MagicMock(), "http://example.com/captcha")
    captcha.value = "TEST123"

    # When
    result = captcha.get_value()

    # Then
    assert result == "TEST123"
