"""Concurrency synchronization utilities"""

import functools
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from typing import Literal, TypeVar


class ShortCircuitWaitException(Exception):
    """raise to immediately stop waiting, e.g. when an operation permanently failed"""

    pass


def wait_until(
    fn: Callable[[], bool],
    wait: float = 1.0,
    max_retries: int = 10,
    strategy: Literal["exponential", "static", "linear"] = "exponential",
    _retries: int = 1,
    _max_wait: float = 240,
) -> bool:
    """Waits until a given condition is true, rechecking it periodically.

    Uses iteration instead of recursion to avoid hitting Python's recursion
    limit with high max_retries values.
    """
    retries = _retries
    current_wait = wait
    while retries <= max_retries:
        try:
            if fn():
                return True
        except ShortCircuitWaitException:
            return False
        except Exception:
            pass

        if current_wait > _max_wait:
            return False
        time.sleep(current_wait)
        if strategy == "linear":
            # MED-02: the previous formula ``(wait / retries) * (retries + 1)``
            # produced a non-obvious arithmetic-progression-of-fractions growth
            # that confused callers (e.g. wait=1, retries=1..3 -> 2, 1.5, ~1.33).
            # Use a true linear schedule: wait * (retries + 1), i.e. each
            # iteration adds exactly ``wait`` seconds on top of the initial.
            current_wait = wait * (retries + 1)
        elif strategy == "exponential":
            current_wait = current_wait * 2
        retries += 1
    return False


T = TypeVar("T")


def retry(function: Callable[..., T], retries=3, sleep=1.0, sleep_before=0, **kwargs) -> T:
    raise_error = None
    if sleep_before > 0:
        time.sleep(sleep_before)
    retries = int(retries)
    for i in range(0, retries + 1):
        try:
            return function(**kwargs)
        except Exception as error:
            raise_error = error
            time.sleep(sleep)
    raise raise_error


def poll_condition(condition, timeout: float = None, interval: float = 0.5) -> bool:
    """
    Poll evaluates the given condition until a truthy value is returned. It does this every `interval` seconds
    (0.5 by default), until the timeout (in seconds, if any) is reached.

    Poll returns True once `condition()` returns a truthy value, or False if the timeout is reached.

    MED-01: ``timeout=None`` means "wait forever" and is honored via a deadline
    computed up front when ``timeout`` is provided. Previously a ``None``
    timeout combined with a never-truthy condition would spin forever with no
    exit path; that is still the documented behaviour of ``timeout=None`` but
    the control flow is now explicit.
    """
    deadline = None
    if timeout is not None:
        deadline = time.monotonic() + timeout

    while not condition():
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            # Sleep no longer than the remaining budget.
            time.sleep(min(interval, remaining))
        else:
            time.sleep(interval)

    return True


def synchronized(lock=None):
    """
    Synchronization decorator as described in
    http://blog.dscpl.com.au/2014/01/the-missing-synchronized-decorator.html.
    """

    def _decorator(wrapped):
        @functools.wraps(wrapped)
        def _wrapper(*args, **kwargs):
            with lock:
                return wrapped(*args, **kwargs)

        return _wrapper

    return _decorator


def sleep_forever():
    while True:
        time.sleep(1)


class SynchronizedDefaultDict(defaultdict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lock = threading.RLock()

    def fromkeys(self, keys, value=None):
        with self._lock:
            return super().fromkeys(keys, value)

    def __getitem__(self, key):
        with self._lock:
            return super().__getitem__(key)

    def __setitem__(self, key, value):
        with self._lock:
            super().__setitem__(key, value)

    def __delitem__(self, key):
        with self._lock:
            super().__delitem__(key)

    def __iter__(self):
        with self._lock:
            return super().__iter__()

    def __len__(self):
        with self._lock:
            return super().__len__()

    def __str__(self):
        with self._lock:
            return super().__str__()


class Once:
    """
    An object that will perform an action exactly once.
    Inspired by Golang's [sync.Once](https://pkg.go.dev/sync#Once) operation.


    ### Example 1

    Multiple threads using `Once::do` to ensure only 1 line is printed.

    ```python
    import threading
    import time
    import random

    greet_once = Once()
    def greet():
        print("This should happen only once.")

    greet_threads = []
    for _ in range(10):
        t = threading.Thread(target=lambda: greet_once.do(greet))
        greet_threads.append(t)
        t.start()

    for t in greet_threads:
        t.join()
    ```


    ### Example 2

    Ensuring idemponent calling to prevent exceptions on multiple calls.

    ```python
    import os

    class Service:
        close_once: sync.Once

    def start(self):
        with open("my-service.txt) as f:
            myfile.write("Started service")

    def close(self):
        # Ensure we only ever delete the file once on close
        self.close_once.do(lambda: os.remove("my-service.txt"))

    ```


    """

    _is_done: bool
    _mu: threading.Lock

    def __init__(self) -> None:
        # These were class-level attributes and therefore SHARED across
        # every Once() instance in the process. Two independent Once objects
        # would see each other's "done" flag, causing subsequent do() calls on
        # fresh instances to become silent no-ops. Moving them to __init__
        # gives each instance its own state + lock, matching Go's sync.Once.
        self._is_done = False
        self._mu = threading.Lock()

    def do(self, fn: Callable[[], None]):
        """
        `do` calls the function `fn()` if-and-only-if `do` has never been called before.

        This ensures idempotent and thread-safe execution.

        If the function raises an exception, `do` considers `fn` as done, where subsequent calls are still no-ops.
        """
        if self._is_done:
            return

        with self._mu:
            if not self._is_done:
                try:
                    fn()
                finally:
                    self._is_done = True


def once_func(fn: Callable[..., T]) -> Callable[..., T | None]:
    """
    Wraps and returns a function that can only ever execute once.

    The first call to the returned function will permanently set the result.
    If the wrapped function raises an exception, this will be re-raised on each subsequent call.

    This function can be used either as a decorator or called directly.

    Direct usage:
    ```python
    delete_file = once_func(os.remove)

    delete_file("myfile.txt")  # deletes the file
    delete_file("myfile.txt")  # does nothing
    ```

    As a decorator:
    ```python
    @once_func
    def delete_file():
        os.remove("myfile.txt")

    delete_file()  # deletes the file
    delete_file()  # does nothing
    ```
    """
    once = Once()

    result, exception = None, None

    def _do(*args, **kwargs):
        nonlocal result, exception
        try:
            result = fn(*args, **kwargs)
        except Exception as e:
            exception = e
            raise

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        once.do(lambda: _do(*args, **kwargs))
        if exception is not None:
            raise exception
        return result

    return wrapper
