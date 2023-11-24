import pyfiglet
from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(format="%(message)s", level=logging.INFO)


class Printers:
    @staticmethod
    def print_logo_tool():
        print(pyfiglet.figlet_format("DevSecOps Bancolombia", font="slant"))

    @staticmethod
    def print_title(title: str):
        logger.info("\n")
        logger.info("*" * len(title))
        logger.info(title)
        logger.info("*" * len(title))
        logger.info("\n")
