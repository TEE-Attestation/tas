#
# TEE Attestation Service - Logging Module
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module is responsible for logging.
#

"""
Logging utilities for TAS (Trusted Attestation Service)

This module provides centralized logging configuration for both library and CLI usage.
"""

import logging
import sys
from typing import Optional, Union


class ColoredFormatter(logging.Formatter):
    """Formatter that adds colors to log levels (for CLI mode)."""

    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",  # Reset
    }

    def format(self, record):
        # Apply color to the log level name
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logging(
    name: str = "tas",
    level: Union[str, int] = logging.INFO,
    cli_mode: bool = False,
    verbose: bool = False,
    quiet: bool = False,
    log_file: Optional[str] = None,
    format_string: Optional[str] = None,
) -> logging.Logger:
    """
    Set up logging configuration for TAS.

    Args:
        name: Logger name (default: "tas")
        level: Logging level (default: INFO)
        cli_mode: Whether running in CLI mode (affects formatting)
        verbose: Enable verbose logging (sets level to DEBUG)
        quiet: Enable quiet mode (sets level to WARNING)
        log_file: Optional file path to write logs to
        format_string: Custom format string (if None, uses appropriate default)

    Returns:
        Configured logger instance
    """
    # Determine log level
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    elif isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    # Get or create logger
    logger = logging.getLogger(name)

    # Clear any existing handlers to avoid duplicates
    logger.handlers.clear()

    # Set the logger level
    logger.setLevel(level)

    # Determine format string based on mode
    if format_string is None:
        if cli_mode:
            # Simple format for CLI tools
            format_string = "%(name)s - %(levelname)s: %(message)s"
        else:
            # More detailed format for library usage
            format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if cli_mode:
        # Use colored formatter for CLI
        formatter = ColoredFormatter(format_string)
    else:
        # Use standard formatter for library
        formatter = logging.Formatter(format_string)

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        # Always use standard formatter for file output (no colors)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "tas") -> logging.Logger:
    """
    Get a logger instance with the given name.

    Args:
        name: Logger name (default: "tas")

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def configure_sev_pytools_logging():
    """Configure sev_pytools logging to use TAS logging settings."""
    # Create sev_pytools logger as child of tas for inheritance
    sev_logger = logging.getLogger("tas.sev_pytools")

    # Configure the direct sev_pytools logger to forward to our tas.sev_pytools
    direct_sev_logger = logging.getLogger("sev_pytools")
    direct_sev_logger.handlers.clear()
    direct_sev_logger.propagate = False
    direct_sev_logger.setLevel(logging.DEBUG)

    # Create handler that forwards messages to our tas.sev_pytools logger
    class TASForwardingHandler(logging.Handler):
        def emit(self, record):
            sev_logger.handle(record)

    forwarding_handler = TASForwardingHandler()
    forwarding_handler.setLevel(logging.DEBUG)
    direct_sev_logger.addHandler(forwarding_handler)

    logger.debug("Configured sev_pytools logging to inherit TAS settings")


def configure_tdx_pytools_logging():
    """Configure tdx_pytools logging to use TAS logging settings."""
    # Create tdx_pytools logger as child of tas for inheritance
    tdx_logger = logging.getLogger("tas.tdx_pytools")

    # Configure the direct tdx_pytools logger to forward to our tas.tdx_pytools
    direct_tdx_logger = logging.getLogger("tdx_pytools")
    direct_tdx_logger.handlers.clear()
    direct_tdx_logger.propagate = False
    direct_tdx_logger.setLevel(logging.DEBUG)

    # Create handler that forwards messages to our tas.tdx_pytools logger
    class TASForwardingHandler(logging.Handler):
        def emit(self, record):
            tdx_logger.handle(record)

    forwarding_handler = TASForwardingHandler()
    forwarding_handler.setLevel(logging.DEBUG)
    direct_tdx_logger.addHandler(forwarding_handler)

    logger.debug("Configured tdx_pytools logging to inherit TAS settings")


def configure_external_logging():
    """Reconfigure external library logging to reflect TAS logging changes."""
    configure_sev_pytools_logging()
    configure_tdx_pytools_logging()


# At the moment these functions are called from logger in the logs rather than their parent
logger = get_logger(__name__)


def log_function_entry(func_name: str, *args, **kwargs) -> None:
    """Log function entry with arguments (for debugging)."""
    args_str = ", ".join(str(arg) for arg in args)
    kwargs_str = ", ".join(f"{k}={v}" for k, v in kwargs.items())
    all_args = ", ".join(filter(None, [args_str, kwargs_str]))
    logger.debug(f"Entering {func_name}({all_args})")


def log_function_exit(func_name: str, result=None) -> None:
    """Log function exit with result (for debugging)."""
    if result is not None:
        logger.debug(f"Exiting {func_name} with result: {result}")
    else:
        logger.debug(f"Exiting {func_name}")
