from enum import Enum

from cryptography.exceptions import (
    InvalidKey,
    AlreadyFinalized,
    UnsupportedAlgorithm,
    InvalidSignature
)

from utils.error_handling import TryExcEnum, TryExceptConf


DEBUG_LABEL = " #debug"


class ErrTxt(str, Enum):
    ERR_INVALID_STR = "ERROR: arg_{0} is not a string. Type:{1}"

    def validate_strings(self, *args) -> None:
        """Validates that each argument provided is a string.

        Parameters:
            *args: Variable length argument list intended to be strings.
        Raises (TypeError):
            If any argument is not a string, indicating the argument number
            and its incorrect type.
        """
        for arg_id, string in enumerate(args):
            if not isinstance(string, str):
                error_text = ErrTxt.ERR_INVALID_STR.value.format(
                    arg_id + 1, str(type(string))
                )
                raise TypeError(error_text)


class TryExceptKeys(TryExcEnum):
    GENERATE_ERROR = TryExceptConf(
        errs=(
            ValueError,
            TypeError,
            UnsupportedAlgorithm
        ), 
        raise_= ValueError,
        txt="Key generation failed" + DEBUG_LABEL
    )
    ENCRYPT_ERROR = TryExceptConf(
        errs=(
            ValueError,
            TypeError,
            UnsupportedAlgorithm
        ), 
        raise_= ValueError,
        txt="Encryption failed" + DEBUG_LABEL
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
        txt="Decryption failed" + DEBUG_LABEL
    )
