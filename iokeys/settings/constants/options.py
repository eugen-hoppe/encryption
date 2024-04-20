from enum import Enum


class Mode(str, Enum):
    PRODUCTION: str = "production"
    DEVELOPMENT: str = "development"
