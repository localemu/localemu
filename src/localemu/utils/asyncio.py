import asyncio
import atexit
import concurrent.futures.thread
import functools
import time
from contextvars import copy_context

from .run import FuncThread
from .threads import TMP_THREADS, start_worker_thread

# reference to named event loop instances
EVENT_LOOPS = {}


class DaemonAwareThreadPool(concurrent.futures.thread.ThreadPoolExecutor):
    """
    This thread pool executor removes the threads it creates from the global ``_thread_queues`` of
    ``concurrent.futures.thread``, which joins all created threads at python exit and will block
    interpreter shutdown if any threads are still running, even if they are daemon threads. Threads created
    by the thread pool will be daemon threads by default if the thread owning the thread pool is also a
    deamon thread.
    """

    def _adjust_thread_count(self) -> None:
        super()._adjust_thread_count()

        for t in self._threads:
            if not t.daemon:
                continue
            try:
                del concurrent.futures.thread._threads_queues[t]
            except KeyError:
                pass


class AdaptiveThreadPool(DaemonAwareThreadPool):
    """Thread pool executor that maintains a maximum of 'core_size' reusable threads in
    the core pool, and creates new thread instances as needed (if the core pool is full)."""

    DEFAULT_CORE_POOL_SIZE = 30

    def __init__(self, core_size=None):
        self.core_size = core_size or self.DEFAULT_CORE_POOL_SIZE
        super().__init__(max_workers=self.core_size)

    def submit(self, fn, *args, **kwargs):
        # if idle threads are available, don't spin new threads
        if self.has_idle_threads():
            return super().submit(fn, *args, **kwargs)

        def _run(*tmpargs):
            return fn(*args, **kwargs)

        thread = start_worker_thread(_run)
        return thread.result_future

    def has_idle_threads(self):
        if hasattr(self, "_idle_semaphore"):
            return self._idle_semaphore.acquire(timeout=0)
        num_threads = len(self._threads)
        return num_threads < self._max_workers


# Thread pool executor for running sync functions in async context.
# Note: For certain APIs like DynamoDB, we need 3x threads for each parallel request,
# as during request processing the API calls out to the DynamoDB API again (recursively).
# (TODO: This could potentially be improved if we move entirely to asyncio functions.)
THREAD_POOL = AdaptiveThreadPool()

# Register the pool's shutdown via Python's stdlib ``atexit`` rather than
# appending it to ``TMP_THREADS``. Historically the pool was appended so that
# ``cleanup_threads_and_processes`` would tear it down, but ``TMP_THREADS`` is
# typed ``list[FuncThread]`` and its prune step in ``start_thread()`` calls
# ``t.is_alive()`` — an attribute that ``ThreadPoolExecutor`` does not have.
# The resulting ``AttributeError`` propagated to every call site of
# ``start_thread`` (including Lambda ``update_function_version`` and the
# analytics publisher), leaving Lambda functions stuck in ``State=Pending``
# forever. ``atexit`` runs during interpreter teardown, is idempotent, and
# matches the precedent set by ``localemu.utils.analytics.publisher``.
atexit.register(THREAD_POOL.shutdown, wait=False)


class AsyncThread(FuncThread):
    def __init__(self, async_func_gen=None, loop=None):
        """Pass a function that receives an event loop instance and a shutdown event,
        and returns an async function."""
        FuncThread.__init__(self, self.run_func, None, name="asyncio-thread")
        self.async_func_gen = async_func_gen
        self.loop = loop
        self.shutdown_event = None

    def run_func(self, *args):
        loop = self.loop or ensure_event_loop()
        self.shutdown_event = asyncio.Event()
        if self.async_func_gen:
            self.async_func = async_func = self.async_func_gen(loop, self.shutdown_event)
            if async_func:
                loop.run_until_complete(async_func)
        loop.run_forever()

    def stop(self, quiet=None):
        if self.shutdown_event:
            self.shutdown_event.set()
            self.shutdown_event = None

    @classmethod
    def run_async(cls, func=None, loop=None):
        thread = cls(func, loop=loop)
        thread.start()
        TMP_THREADS.append(thread)
        return thread


async def run_sync(func, *args, thread_pool=None, **kwargs):
    loop = asyncio.get_running_loop()
    thread_pool = thread_pool or THREAD_POOL
    func_wrapped = functools.partial(func, *args, **kwargs)
    return await loop.run_in_executor(thread_pool, copy_context().run, func_wrapped)


def run_coroutine(coroutine, loop=None):
    """Run an async coroutine in a threadsafe way in the main event loop"""
    loop = loop or get_main_event_loop()
    future = asyncio.run_coroutine_threadsafe(coroutine, loop)
    return future.result()


def ensure_event_loop():
    """Ensure that an event loop is defined for the currently running thread"""
    try:
        return asyncio.get_event_loop()
    except Exception:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


def get_main_event_loop():
    return get_named_event_loop("_main_")


def get_named_event_loop(name):
    result = EVENT_LOOPS.get(name)
    if result:
        return result

    def async_func_gen(loop, shutdown_event):
        EVENT_LOOPS[name] = loop

    AsyncThread.run_async(async_func_gen)
    # 2.4 fix: poll with short sleep instead of blocking 1s
    for _ in range(50):
        if name in EVENT_LOOPS:
            return EVENT_LOOPS[name]
        time.sleep(0.02)
    return EVENT_LOOPS[name]


async def receive_from_queue(queue):
    from localemu.runtime import events

    def get():
        # run in a retry loop (instead of blocking forever) to allow for graceful shutdown
        while True:
            try:
                if events.infra_stopping.is_set():
                    return
                return queue.get(timeout=1)
            except Exception:
                pass

    msg = await run_sync(get)
    return msg
