import re
from io import BytesIO

import pytesseract
from PIL import Image


class Captcha:
    def __init__(self, session, url):
        self.url = url
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

        req = self.session.get(f"{self.url}/internal-panel")

        print(req.text)

        img = re.search(r'<img src="([^"]*)"', req.text).group(1)
        print(f"img: {img}")
        req_img = self.session.get(f"{self.url}{img}").content
        self.image = Image.open(BytesIO(req_img)).convert("L")

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
