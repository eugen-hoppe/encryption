from settings.constants.exceptions import ErrTxt


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
