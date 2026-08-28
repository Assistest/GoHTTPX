import ctypes
import os
import subprocess
import threading
from ctypes import wintypes as w

import msvcrt


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR), ("title", w.LPWSTR),
        ("x", w.DWORD), ("y", w.DWORD), ("x_size", w.DWORD), ("y_size", w.DWORD),
        ("x_chars", w.DWORD), ("y_chars", w.DWORD), ("fill", w.DWORD), ("flags", w.DWORD),
        ("show", w.WORD), ("reserved_size", w.WORD), ("reserved_bytes", ctypes.c_void_p),
        ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [("startup", _StartupInfo), ("attributes", ctypes.c_void_p)]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


class _BasicLimit(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64), ("flags", w.DWORD),
        ("min_working_set", ctypes.c_size_t), ("max_working_set", ctypes.c_size_t),
        ("active_limit", w.DWORD), ("affinity", ctypes.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD),
    ]


class _ExtendedLimit(ctypes.Structure):
    _fields_ = [
        ("basic", _BasicLimit), ("io_counters", ctypes.c_uint64 * 6),
        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
        ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t),
    ]


_kernel = ctypes.WinDLL("kernel32", use_last_error=True)
for _name, _args, _result in [
    ("CreateJobObjectW", [ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
    ("SetInformationJobObject", [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
    ("InitializeProcThreadAttributeList", [ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(ctypes.c_size_t)], w.BOOL),
    ("UpdateProcThreadAttribute", [ctypes.c_void_p, w.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p], w.BOOL),
    ("DeleteProcThreadAttributeList", [ctypes.c_void_p], None),
    ("CreateProcessW", [w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD, ctypes.c_void_p, w.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(_ProcessInfo)], w.BOOL),
    ("CloseHandle", [w.HANDLE], w.BOOL),
    ("WaitForSingleObject", [w.HANDLE, w.DWORD], w.DWORD),
    ("GetExitCodeProcess", [w.HANDLE, ctypes.POINTER(w.DWORD)], w.BOOL),
]:
    _function = getattr(_kernel, _name)
    _function.argtypes = _args
    _function.restype = _result


def _check(result):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result


class JobProcess:
    """Job 只由 Python 持有；父进程来不及清理时仍由内核回收子进程。"""

    def __init__(self, args):
        self._lock = threading.RLock()
        self._job = None
        self._process = None
        self.returncode = None
        self.stdin = self.stdout = self.stderr = None
        descriptors = []
        attributes = None
        initialized = False
        process_info = _ProcessInfo()
        try:
            self._job = _check(_kernel.CreateJobObjectW(None, None))
            limits = _ExtendedLimit()
            limits.basic.flags = 0x2000
            _check(_kernel.SetInformationJobObject(self._job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
            for _ in range(3):
                descriptors.extend(os.pipe())
            child_fds = [descriptors[0], descriptors[3], descriptors[5]]
            child_handles = (w.HANDLE * 3)(*(msvcrt.get_osfhandle(fd) for fd in child_fds))
            for handle in child_handles:
                os.set_handle_inheritable(handle, True)
            size = ctypes.c_size_t()
            _kernel.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
            attributes = ctypes.create_string_buffer(size.value)
            _check(_kernel.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size)))
            initialized = True
            jobs = (w.HANDLE * 1)(self._job)
            _check(_kernel.UpdateProcThreadAttribute(attributes, 0, 0x0002000D, jobs, ctypes.sizeof(jobs), None, None))
            _check(_kernel.UpdateProcThreadAttribute(attributes, 0, 0x00020002, child_handles, ctypes.sizeof(child_handles), None, None))
            startup = _StartupInfoEx()
            startup.startup.cb = ctypes.sizeof(startup)
            startup.startup.flags = 0x100
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = child_handles
            startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(arg) for arg in args]))
            _check(_kernel.CreateProcessW(str(args[0]), command, None, None, True, 0x08080000, None, None, ctypes.byref(startup), ctypes.byref(process_info)))
            self._process = process_info.process
            self.pid = process_info.pid
            _kernel.CloseHandle(process_info.thread)
            for fd in child_fds:
                os.close(fd)
                descriptors.remove(fd)
            self.stdin = os.fdopen(descriptors.pop(0), "wb", buffering=0)
            self.stdout = os.fdopen(descriptors.pop(0), "rb", buffering=0)
            self.stderr = os.fdopen(descriptors.pop(0), "rb", buffering=0)
        except BaseException:
            self.close()
            raise
        finally:
            if initialized:
                _kernel.DeleteProcThreadAttributeList(attributes)
            for fd in descriptors:
                os.close(fd)

    def poll(self):
        with self._lock:
            if self.returncode is not None or self._process is None:
                return self.returncode
            result = _kernel.WaitForSingleObject(self._process, 0)
            if result == 258:
                return None
            if result != 0:
                raise ctypes.WinError(ctypes.get_last_error())
            code = w.DWORD()
            _check(_kernel.GetExitCodeProcess(self._process, ctypes.byref(code)))
            self.returncode = code.value
            return self.returncode

    def wait(self, timeout=5.0):
        with self._lock:
            if self._process is None:
                return self.returncode
            result = _kernel.WaitForSingleObject(self._process, max(0, min(int(timeout * 1000), 0xFFFFFFFE)))
            if result == 258:
                raise subprocess.TimeoutExpired("managed Go", timeout)
            if result != 0:
                raise ctypes.WinError(ctypes.get_last_error())
            return self.poll()

    def kill(self):
        with self._lock:
            if self._job is not None:
                _check(_kernel.CloseHandle(self._job))
                self._job = None

    def close(self):
        with self._lock:
            self.kill()
            if self._process is not None:
                self.wait()
                _kernel.CloseHandle(self._process)
                self._process = None
            for stream in (self.stdin, self.stdout, self.stderr):
                if stream is not None:
                    stream.close()
