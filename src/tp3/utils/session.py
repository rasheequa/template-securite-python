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
        self.captcha_url = ""
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.session = requests.Session()
        self.host = ""
        self.port = 0
        self.key = b""
        self.tokenToXor = b""

    def _fuzz_endpoint(self):
        """
        Fuzzes the endpoint to find the correct URL.

        Returns:
            str: The correct URL.
        """
        logger.debug("Fuzzing endpoint")
        word = "internal-panel"
        wordlist = map(str.strip, open("wordlist.txt", "r").readlines())
        for word in wordlist:
            logger.debug(f"trying {self.url}/{word}")
            req = self.session.get(f"{self.url}/{word}")
            if req.status_code == 200 and "captcha" in req.text:
                logger.debug(f"Word found: {word}")
                self.captcha_url = f"{self.url}/{word}"
                break
        else:
            logger.debug("Captcha url endpoint not found, continue with default internal-panel")
            self.captcha_url = f"{self.url}/internal-panel"

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        self._fuzz_endpoint()
        captcha = Captcha(self.session, self.url, self.captcha_url)
        for i in range(5):
            logger.debug(f"Attempt {i + 1} to capture and solve captcha")
            captcha.capture()
            captcha.solve()
            self.captcha_value = captcha.get_value()
            logger.debug(f"captcha_value: {self.captcha_value}")

            logger.debug("sending request to get json")
            get_json = self.session.post(f"{self.captcha_url}", data={"captcha": self.captcha_value})
            data = get_json.json()
            if data.get("host"):
                break
        else:
            logger.error("Failed to get valid response after 5 attempts")
            raise RuntimeError("Failed to get valid response after 5 attempts")

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
        response = target.recvline(drop=True).decode()

        while not response.startswith("OK "):
            token = base64.b64decode(response)
            logger.debug(f"token: {token}")
            self.tokenToXor = token
            keyToSend = self._process_response()
            logger.debug(f"senf key to serv: {keyToSend}")
            target.send(keyToSend.encode())
            response = target.recvline(drop=True).decode()
            logger.debug(f"response: {response}")

        self.valid_flag = response.removeprefix("OK ")

    def _process_response(self):
        """
        Processes the response.
        """
        logger.debug(f"xoring token: {self.tokenToXor} with key: {self.key}")
        xor_result = bytes(a ^ b for a, b in zip(self.tokenToXor, cycle(self.key)))
        xored = xor_result.decode()
        logger.debug(f"xored value: {xored}")
        return xored

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
