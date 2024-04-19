from settings.constants.exceptions import ErrTxt


def validate_strings(*args) -> None:
    """Validation of Strings

    https://github.com/eugen-hoppe/encryption/blob/main/docs/v4.md#d17a
    """
    for arg_id, string in enumerate(args):
        if not isinstance(string, str):
            error_text = ErrTxt.ERR_INVALID_STR.value.format(
                arg_id + 1, str(type(string))
            )
            raise TypeError(error_text)
