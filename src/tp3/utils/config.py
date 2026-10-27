from src.config import logging

logger = logging.getLogger("TP3")
logger.setLevel(logging.DEBUG)
logging.getLogger("pwnlib").setLevel(logging.ERROR)
