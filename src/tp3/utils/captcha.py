import re
from io import BytesIO

import pytesseract
from PIL import Image

from src.tp3.utils.config import logger


class Captcha:
    def __init__(self, session, url, captcha_url):
        self.url = url
        self.captcha_url = captcha_url
        self.image = ""
        self.value = ""
        self.session = session

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        self.value = pytesseract.image_to_string(
            self.image, config="--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        ).strip()

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        logger.debug(f"Capturing captcha from {self.captcha_url}")
        req = self.session.get(f"{self.captcha_url}")

        logger.debug(req.text)

        img = re.search(r'<img src="([^"]*)"', req.text).group(1)
        logger.debug(f"img: {img}")
        req_img = self.session.get(f"{self.url}{img}").content
        self.image = Image.open(BytesIO(req_img)).convert("L")

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
