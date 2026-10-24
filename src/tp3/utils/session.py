import requests

from src.tp3.utils.captcha import Captcha


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

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.session, self.url)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.flag_value = "FIXME"
        return self.captcha_value  # temporary, just to test if refactos working

    def submit_request(self):
        """
        Sends the flag and captcha.
        """

    def process_response(self):
        """
        Processes the response.
        """

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
