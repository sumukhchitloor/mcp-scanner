"""Logging utilities for the MCP security scanner."""

import logging
import sys
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console

console = Console()

def setup_logger(name: str = "mcp_scanner", level: str = "INFO") -> logging.Logger:
    """
    Setup a logger with rich formatting.
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Remove existing handlers to avoid duplicate logs
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Set level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    
    # Create rich handler
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True
    )
    
    # Set format
    formatter = logging.Formatter(
        fmt="%(message)s",
        datefmt="[%X]"
    )
    rich_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(rich_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger instance."""
    if name is None:
        name = "mcp_scanner"
    return logging.getLogger(name)
