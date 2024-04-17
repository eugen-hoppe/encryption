from enum import Enum

from cryptography.exceptions import (
    InvalidKey,
    AlreadyFinalized,
    UnsupportedAlgorithm,
    InvalidSignature
)

from utils.error_handling import TryExcEnum, TryExceptConf


class ErrTxt(str, Enum):
    ERR_INVALID_STR = "ERROR: arg_{0} is not a string. Type:{1}"

    def fmt(self, *args, **kwargs):
        return self.format(*args, **kwargs)



class TryExceptKeys(TryExcEnum):
    GENERATE_ERROR = TryExceptConf(
        errs=(
            ValueError,
            TypeError,
            UnsupportedAlgorithm
        ), 
        raise_= ValueError,
        txt="Key generation failed"
    )
    ENCRYPT_ERROR = TryExceptConf(
        errs=(
            ValueError,
            TypeError,
            UnsupportedAlgorithm
        ), 
        raise_= ValueError,
        txt="Encryption failed"
    )
    DECRYPT_ERROR = TryExceptConf(
        errs=(
            ValueError,
            TypeError,
            InvalidKey,
            UnsupportedAlgorithm,
            InvalidSignature,
            AlreadyFinalized
        ),
        raise_= ValueError,
        txt="Decryption failed"
    )
