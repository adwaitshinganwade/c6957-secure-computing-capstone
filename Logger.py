import logging
import sys

class Colors:
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    RED = '\e[0;31m'
    END = '\033[0m'

class Logger:
    """
    A wrapper around Python's standard logging system. `Logger` uses distinct colors for
    some logging levels (currently warning and error).
    """
    
    # TODO - validation for log level
    def __init__(self, logger_name, path_to_log_file: str, log_level):
        self.__log_file = path_to_log_file
        self.__logger_name = logger_name
        self.__logger = logging.getLogger(self.__logger_name)

        # Set colors for logging levels
        self.__WARN_COLOR = Colors.CYAN
        self.__ERROR_COLOR = Colors.RED

        # Set the default method to log
        self.__default_log_method = Logger.info

        logging.basicConfig(level=log_level, handlers=[logging.FileHandler(self.__log_file), logging.StreamHandler(sys.stdout)],
                    format="%(asctime)s - %(levelname)-8s - %(name)s - %(message)s")
        

    def log(self, message:str):
        self.__default_log_method(message)

    def info(self, message: str):
        self.__logger.info(message)

    def warning(self, message:str):
        self.__logger.warning(f"{self.__WARN_COLOR}{message}{Colors.END}")

    def error(self, message:str):
        self.__logger.error(f"{self.__ERROR_COLOR}{message}{Colors.END}")

    def debug(self, message:str):
        self.__logger.debug(message)


