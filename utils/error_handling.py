from dataclasses import dataclass
from enum import Enum
from typing import Callable, Tuple, Type, Optional
from functools import wraps


@dataclass
class TryExceptConf:
    errs: tuple[type[Exception], ...] = Exception
    raise_: type[Exception] | None = None
    txt: str = ""

    def dictionary(self) -> dict:
        return {"errs": self.errs, "raise_": self.raise_, "txt": self.txt}


class TryExcEnum(Enum):
    def kw(cls: Enum) -> dict:
        try_except_conf: TryExceptConf = cls.value
        return try_except_conf.dictionary()


def try_except(
    errs: Tuple[Type[Exception], ...] = (Exception,),
    raise_: Optional[Type[Exception]] = None,
    txt: str = "",
) -> Callable:
    """A decorator that wraps a function to handle exceptions

    docs:
    - https://gist.github.com/eugen-hoppe/c20688d17c7682cf1284718a655d0e0d
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: any, **kwargs: any) -> any:
            try:
                return func(*args, **kwargs)
            except errs as err:
                if raise_ is not None:
                    from_error = err if "#debug" in txt else None
                    msg_ = txt + " (INFO: add '#debug' for traceback chain)"
                    raise raise_(msg_) from from_error
                raise err

        return wrapper

    return decorator
