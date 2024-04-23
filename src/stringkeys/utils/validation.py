import base64

from stringkeys.settings.constants.exceptions import (
    ErrTxt,
    PayloadTooLargeError,
    StringInputError,
    InvalidKeyLengthError,
)


def validate_strings(*args) -> None:
    """Validation of Strings

    https://github.com/eugen-hoppe/encryption/blob/main/docs/utils.md#40419b
    """
    for arg_id, string in enumerate(args):
        if not isinstance(string, str):
            error_text = ErrTxt.ERR_INVALID_STR.value.format(
                arg_id + 1, str(type(string))
            )
            raise StringInputError(error_text)


def validate_payload_length(payload: str, max_length: int) -> None:
    """Validate that the payload does not exceed the maximum allowed length."""
    if len(payload.encode("utf-8")) > max_length:
        raise PayloadTooLargeError("Payload is too large for asymmetric encryption")


def validate_key_min_length(symmetric_key: str, options_key_size: int = 32):
    """Validate that the key does not exceed the minimum allowed length."""
    key_bytes = base64.urlsafe_b64decode(symmetric_key)
    print(len(key_bytes), " - "*30)
    if len(key_bytes) < options_key_size:
        raise InvalidKeyLengthError(options_key_size, len(key_bytes))
