from stringkeys.settings.constants.exceptions import (
    ErrTxt, PayloadTooLargeError, StringInputError,
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
    if len(payload.encode('utf-8')) > max_length:
        raise PayloadTooLargeError("Payload is too large for RSA encryption")
