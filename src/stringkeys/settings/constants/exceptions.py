from enum import Enum

from cryptography.exceptions import (
    InvalidKey,
    AlreadyFinalized,
    UnsupportedAlgorithm,
    InvalidSignature,
)

from stringkeys.utils.error_handling import TryExcEnum, TryExceptConf
from stringkeys.settings.config import MODE
from stringkeys.settings.constants.options import Mode


DEBUG_TAG = "#debug" if MODE == Mode.DEVELOPMENT else "#prod"


class ErrTxt(str, Enum):
    ERR_INVALID_STR = "ERROR: arg_{0} is not a string. Type:{1}"


class TryExceptKeys(TryExcEnum):
    GENERATE_ERROR = TryExceptConf(
        errs=(
            ValueError,
            TypeError,
            UnsupportedAlgorithm,
        ),
        raise_=ValueError,
        txt=f"Key generation failed {DEBUG_TAG}",
    )
    ENCRYPT_ERROR = TryExceptConf(
        errs=(
            ValueError,
            TypeError,
            UnsupportedAlgorithm,
        ),
        raise_=ValueError,
        txt=f"Encryption failed {DEBUG_TAG}",
    )
    DECRYPT_ERROR = TryExceptConf(
        errs=(
            ValueError,
            TypeError,
            InvalidKey,
            UnsupportedAlgorithm,
            InvalidSignature,
            AlreadyFinalized,
        ),
        raise_=ValueError,
        txt=f"Decryption failed {DEBUG_TAG}",
    )
