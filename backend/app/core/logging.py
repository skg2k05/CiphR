import logging
import sys
from app.core.config import settings

def setup_logging():
    log_level = logging.getLevelName(settings.LOG_LEVEL.upper())
    
    # Basic configuration for standard output
    logging.basicConfig(
        stream=sys.stdout,
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # You can add more complex handlers here if needed (e.g., JSON logging, file handlers)
    
    logger = logging.getLogger("ciphr")
    return logger

logger = setup_logging()
