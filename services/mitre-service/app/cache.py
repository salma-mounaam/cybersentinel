from functools import lru_cache


@lru_cache(maxsize=1)
def get_cached_techniques():
    return {}