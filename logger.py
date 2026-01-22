"""
Enhanced Logging Utility with Colors and Structured Output
Provides consistent, readable logging across all modules.
"""

import sys
from datetime import datetime
from enum import Enum


class LogLevel(Enum):
    """Log level enumeration"""
    DEBUG = 0
    INFO = 1
    SUCCESS = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    ATTACK = 6
    SECURITY = 7


class Colors:
    """ANSI color codes for terminal output"""
    # Text colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Reset
    RESET = '\033[0m'
    
    @staticmethod
    def disable():
        """Disable all colors (for non-terminal output)"""
        for attr in dir(Colors):
            if not attr.startswith('_') and attr.isupper():
                setattr(Colors, attr, '')


class Logger:
    """Enhanced logger with colors and structured output"""
    
    # Global settings
    show_timestamp = True
    show_level = True
    min_level = LogLevel.DEBUG
    use_colors = True
    
    # Color mappings for log levels
    LEVEL_COLORS = {
        LogLevel.DEBUG: Colors.DIM + Colors.WHITE,
        LogLevel.INFO: Colors.CYAN,
        LogLevel.SUCCESS: Colors.BRIGHT_GREEN,
        LogLevel.WARNING: Colors.YELLOW,
        LogLevel.ERROR: Colors.BRIGHT_RED,
        LogLevel.CRITICAL: Colors.BG_RED + Colors.BRIGHT_WHITE,
        LogLevel.ATTACK: Colors.BRIGHT_MAGENTA,
        LogLevel.SECURITY: Colors.BRIGHT_YELLOW,
    }
    
    LEVEL_PREFIXES = {
        LogLevel.DEBUG: "🔍 DEBUG",
        LogLevel.INFO: "ℹ️  INFO",
        LogLevel.SUCCESS: "✓ SUCCESS",
        LogLevel.WARNING: "⚠️  WARNING",
        LogLevel.ERROR: "✗ ERROR",
        LogLevel.CRITICAL: "🚨 CRITICAL",
        LogLevel.ATTACK: "⚔️  ATTACK",
        LogLevel.SECURITY: "🔒 SECURITY",
    }
    
    @classmethod
    def _format_message(cls, level: LogLevel, component: str, message: str) -> str:
        """Format a log message with colors and metadata"""
        parts = []
        
        # Timestamp
        if cls.show_timestamp:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            if cls.use_colors:
                parts.append(f"{Colors.DIM}[{timestamp}]{Colors.RESET}")
            else:
                parts.append(f"[{timestamp}]")
        
        # Level
        if cls.show_level:
            level_str = cls.LEVEL_PREFIXES.get(level, level.name)
            if cls.use_colors:
                color = cls.LEVEL_COLORS.get(level, "")
                parts.append(f"{color}{level_str:12}{Colors.RESET}")
            else:
                parts.append(f"{level_str:12}")
        
        # Component
        if component:
            if cls.use_colors:
                parts.append(f"{Colors.BOLD}[{component}]{Colors.RESET}")
            else:
                parts.append(f"[{component}]")
        
        # Message
        if cls.use_colors and level in cls.LEVEL_COLORS:
            parts.append(f"{cls.LEVEL_COLORS[level]}{message}{Colors.RESET}")
        else:
            parts.append(message)
        
        return " ".join(parts)
    
    @classmethod
    def log(cls, level: LogLevel, component: str, message: str):
        """Generic log method"""
        if level.value < cls.min_level.value:
            return
        
        formatted = cls._format_message(level, component, message)
        print(formatted, file=sys.stdout if level.value < LogLevel.ERROR.value else sys.stderr)
    
    @classmethod
    def debug(cls, component: str, message: str):
        """Log debug message"""
        cls.log(LogLevel.DEBUG, component, message)
    
    @classmethod
    def info(cls, component: str, message: str):
        """Log info message"""
        cls.log(LogLevel.INFO, component, message)
    
    @classmethod
    def success(cls, component: str, message: str):
        """Log success message"""
        cls.log(LogLevel.SUCCESS, component, message)
    
    @classmethod
    def warning(cls, component: str, message: str):
        """Log warning message"""
        cls.log(LogLevel.WARNING, component, message)
    
    @classmethod
    def error(cls, component: str, message: str, exception: Exception = None):
        """Log error message"""
        cls.log(LogLevel.ERROR, component, message)
        if exception:
            cls.log(LogLevel.ERROR, component, f"  Exception: {type(exception).__name__}: {str(exception)}")
    
    @classmethod
    def critical(cls, component: str, message: str, exception: Exception = None):
        """Log critical error message"""
        cls.log(LogLevel.CRITICAL, component, message)
        if exception:
            cls.log(LogLevel.CRITICAL, component, f"  Exception: {type(exception).__name__}: {str(exception)}")
    
    @classmethod
    def attack(cls, component: str, message: str):
        """Log attack-related message"""
        cls.log(LogLevel.ATTACK, component, message)
    
    @classmethod
    def security(cls, component: str, message: str):
        """Log security-related message"""
        cls.log(LogLevel.SECURITY, component, message)
    
    @classmethod
    def section(cls, title: str, char: str = "=", width: int = 70):
        """Print a section header"""
        if cls.use_colors:
            print(f"\n{Colors.BOLD}{Colors.BRIGHT_CYAN}{char * width}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.BRIGHT_CYAN}{title.center(width)}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.BRIGHT_CYAN}{char * width}{Colors.RESET}\n")
        else:
            print(f"\n{char * width}")
            print(title.center(width))
            print(f"{char * width}\n")
    
    @classmethod
    def subsection(cls, title: str, char: str = "-", width: int = 70):
        """Print a subsection header"""
        if cls.use_colors:
            print(f"\n{Colors.BRIGHT_BLUE}{char * width}{Colors.RESET}")
            print(f"{Colors.BRIGHT_BLUE}{Colors.BOLD}{title}{Colors.RESET}")
            print(f"{Colors.BRIGHT_BLUE}{char * width}{Colors.RESET}\n")
        else:
            print(f"\n{char * width}")
            print(title)
            print(f"{char * width}\n")
    
    @classmethod
    def table_row(cls, *columns, widths=None):
        """Print a formatted table row"""
        if widths is None:
            widths = [20] * len(columns)
        
        row = " | ".join(str(col).ljust(width) for col, width in zip(columns, widths))
        if cls.use_colors:
            print(f"{Colors.CYAN}{row}{Colors.RESET}")
        else:
            print(row)
    
    @classmethod
    def separator(cls, char: str = "-", width: int = 70):
        """Print a separator line"""
        if cls.use_colors:
            print(f"{Colors.DIM}{char * width}{Colors.RESET}")
        else:
            print(char * width)
    
    @classmethod
    def key_value(cls, key: str, value: str, key_width: int = 25):
        """Print a key-value pair"""
        if cls.use_colors:
            print(f"{Colors.BRIGHT_WHITE}{key.ljust(key_width)}{Colors.RESET}: {Colors.CYAN}{value}{Colors.RESET}")
        else:
            print(f"{key.ljust(key_width)}: {value}")
    
    @classmethod
    def hex_dump(cls, data: bytes, label: str = "Data", max_bytes: int = 32):
        """Print hexadecimal dump of data"""
        hex_str = data[:max_bytes].hex()
        display = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        if len(data) > max_bytes:
            display += f" ... ({len(data)} bytes total)"
        
        if cls.use_colors:
            print(f"{Colors.BRIGHT_WHITE}{label}:{Colors.RESET} {Colors.YELLOW}{display}{Colors.RESET}")
        else:
            print(f"{label}: {display}")


# Convenience function for simple prints with colors
def cprint(message: str, color: str = "", bold: bool = False, end: str = "\n"):
    """Colored print utility"""
    if Logger.use_colors:
        prefix = f"{Colors.BOLD if bold else ''}{color}"
        print(f"{prefix}{message}{Colors.RESET}", end=end)
    else:
        print(message, end=end)


# Convenience functions for common use cases
def print_banner(text: str):
    """Print a prominent banner"""
    Logger.section(text, "=", 70)


def print_error_box(title: str, message: str):
    """Print an error in a box"""
    if Logger.use_colors:
        print(f"\n{Colors.BG_RED}{Colors.BRIGHT_WHITE} {title} {Colors.RESET}")
        print(f"{Colors.BRIGHT_RED}{message}{Colors.RESET}\n")
    else:
        print(f"\n[ERROR] {title}")
        print(f"{message}\n")


def print_success_box(title: str, message: str):
    """Print a success message in a box"""
    if Logger.use_colors:
        print(f"\n{Colors.BG_GREEN}{Colors.BLACK} {title} {Colors.RESET}")
        print(f"{Colors.BRIGHT_GREEN}{message}{Colors.RESET}\n")
    else:
        print(f"\n[SUCCESS] {title}")
        print(f"{message}\n")


# Initialize colors based on terminal support
if not sys.stdout.isatty():
    Colors.disable()
    Logger.use_colors = False
