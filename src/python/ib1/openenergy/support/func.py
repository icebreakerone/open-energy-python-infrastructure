from functools import lru_cache, wraps
from time import monotonic_ns


def timed_lru_cache(_func=None, *, seconds: int = 600, maxsize: int = 128, typed: bool = False):
    """Extension of functools lru_cache with a timeout

    See https://gist.github.com/Morreski/c1d08a3afa4040815eafd3891e16b945

    :param seconds:
        Timeout in seconds to clear the whole cache, default 10 minutes.
    :param maxsize:
        Maximum size of the cache
    :param typed:
        Whether to treat the same values of different types as different values
    """
    def wrapper_cache(f):
        f = lru_cache(maxsize=maxsize, typed=typed)(f)
        f.delta = seconds * 10 ** 9
        f.expiration = monotonic_ns() + f.delta

        @wraps(f)
        def wrapped_f(*args, **kwargs):
            if monotonic_ns() >= f.expiration:
                f.cache_clear()
                f.expiration = monotonic_ns() + f.delta
            return f(*args, **kwargs)

        wrapped_f.cache_info = f.cache_info
        wrapped_f.cache_clear = f.cache_clear
        return wrapped_f

    # To allow decorator to be used without arguments
    if _func is None:
        return wrapper_cache
    else:
        return wrapper_cache(_func)
