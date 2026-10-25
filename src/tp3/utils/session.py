import base64
from itertools import cycle

import requests
from pwn import remote

from src.tp3.utils.captcha import Captcha
from tp3.utils.config import logger


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.session = requests.Session()
        self.host = ""
        self.port = 0
        self.key = b""
        self.tokenToXor = b""

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.session, self.url)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        logger.debug(f"captcha_value: {self.captcha_value}")

        logger.debug("sending request to get json")
        get_json = self.session.post(f"{self.url}/internal-panel", data={"captcha": self.captcha_value})

        data = get_json.json()

        self.flag_value = data.get("flag1", "")
        self.host = data.get("host", "")
        self.port = data.get("port", 0)
        self.key = bytes.fromhex(data.get("key", ""))
        logger.debug(f"key: {self.key}")
        return self.flag_value

    def submit_request(self):
        """
        Sends the flag and captcha.
        """
        target = remote(self.host, self.port)
        target.recvuntil(b"token.\n")
        logger.debug("reading whats in tcp connection: ")
        b64token = target.recvline(drop=True).decode()
        token = base64.b64decode(b64token)
        logger.debug(f"token: {token}")
        self.tokenToXor = token

    def process_response(self):
        """
        Processes the response.
        """
        logger.debug(f"xoring token: {self.tokenToXor} with key: {self.key}")
        xor_result = bytes(a ^ b for a, b in zip(self.tokenToXor, cycle(self.key)))
        self.valid_flag = xor_result.decode()
        logger.debug(f"valid_flag: {self.valid_flag}")

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
