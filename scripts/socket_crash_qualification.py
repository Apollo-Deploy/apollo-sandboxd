#!/usr/bin/env python3
"""Linux x86_64 syscall-boundary SIGKILL tests against the actual Rust Socket::bind.

No production injection hook is used. ptrace observes only this script's child
test process and its threads; every filesystem effect is inside a private fixture.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import time

PTRACE_TRACEME, PTRACE_PEEKDATA = 0, 2
PTRACE_GETREGS, PTRACE_SYSCALL = 12, 24
PTRACE_SETOPTIONS = 0x4200
OPTIONS = 1 | 8 | 0x00100000  # TRACESYSGOOD | TRACECLONE | EXITKILL
WALL = 0x40000000
ATTRIBUTE = b"user.apollo_sandboxd.socket_owner"
DIRECTORY = b".sandboxd-socket-stage"
DRIVER = "api::socket::tests::crash_driver"


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
        "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
        "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs")]


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.ptrace.restype = ctypes.c_long
LIBC.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]


def trace(request, pid, address=0, data=0):
    ctypes.set_errno(0)
    result = LIBC.ptrace(request, pid, address, data)
    error = ctypes.get_errno()
    if result == -1 and error:
        raise OSError(error, os.strerror(error))
    return result


def traceme():
    trace(PTRACE_TRACEME, 0)


def string(pid, address):
    result = bytearray()
    for offset in range(0, 256, 8):
        word = trace(PTRACE_PEEKDATA, pid, address + offset)
        block = (word & ((1 << 64) - 1)).to_bytes(8, "little")
        if 0 in block:
            result.extend(block[:block.index(0)])
            return bytes(result)
        result.extend(block)
    raise RuntimeError("traced path exceeds qualification bound")


def run_case(binary, phase, output, recovery_binary=None):
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="socket-crash-") as fixture:
        os.chmod(fixture, 0o700)
        environment = dict(os.environ, SANDBOXD_SOCKET_TEST_DIRECTORY=fixture)
        command = [str(binary), "--ignored", "--exact", DRIVER, "--nocapture"]
        log_path = output / (phase + ".log")
        with log_path.open("wb") as log:
            process = subprocess.Popen(command, env=environment, stdout=log,
                                       stderr=subprocess.STDOUT, preexec_fn=traceme,
                                       start_new_session=True)
            tids = {process.pid}
            killed, reached, xattrs, legacy_truncations = False, False, 0, 0
            event = None
            try:
                _, status = os.waitpid(process.pid, 0)
                if not os.WIFSTOPPED(status):
                    raise RuntimeError("traced child failed before exec stop")
                trace(PTRACE_SETOPTIONS, process.pid, 0, OPTIONS)
                trace(PTRACE_SYSCALL, process.pid)
                deadline = time.monotonic() + 30
                while tids:
                    tid, status = os.waitpid(-1, WALL | os.WNOHANG)
                    if not tid:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("syscall qualification timed out")
                        time.sleep(0.002)
                        continue
                    if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                        tids.discard(tid)
                        if tid == process.pid:
                            process.returncode = os.waitstatus_to_exitcode(status)
                        continue
                    tids.add(tid)
                    stop = os.WSTOPSIG(status)
                    if stop == (signal.SIGTRAP | 0x80) and not killed:
                        registers = Registers()
                        trace(PTRACE_GETREGS, tid, 0, ctypes.addressof(registers))
                        syscall = registers.orig_rax
                        successful = registers.rax == 0
                        if syscall == 190 and successful and string(tid, registers.rsi) == ATTRIBUTE:
                            xattrs += 1
                        if syscall == 77 and successful:
                            target = os.readlink(f"/proc/{tid}/fd/{registers.rdi}")
                            if target.endswith("/socket-owner.cbor"):
                                legacy_truncations += 1
                        reached = successful and (
                            (phase == "created" and syscall == 258 and string(tid, registers.rsi) == DIRECTORY)
                            or (phase == "claimed" and syscall == 74 and xattrs == 1)
                            or (phase == "bound" and syscall == 49)
                            or (phase == "prepared" and syscall == 74 and xattrs == 3)
                            or (phase == "renamed" and syscall == 316 and xattrs == 3)
                            or (phase == "committed" and syscall == 74 and xattrs == 4)
                            or (phase == "legacy_ready" and syscall == 74 and legacy_truncations == 1))
                        if reached:
                            event = {"tid": tid, "syscall": syscall,
                                     "successful_owner_xattr_writes": xattrs}
                            os.killpg(process.pid, signal.SIGKILL)
                            killed = True
                    if not killed:
                        # Clone stops/exec traps are bookkeeping; forward genuine signals.
                        deliver = 0 if stop in (signal.SIGTRAP, signal.SIGSTOP, signal.SIGTRAP | 0x80) else stop
                        trace(PTRACE_SYSCALL, tid, 0, deliver)
                if not reached or process.returncode != -signal.SIGKILL:
                    raise RuntimeError("required crash boundary was not reached")
            finally:
                if tids:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    while tids:
                        try:
                            tid, status = os.waitpid(-1, WALL)
                            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                                tids.discard(tid)
                        except ChildProcessError:
                            tids.clear()
            before = {"public_socket": (Path(fixture) / "s").exists(),
                      "staged_socket": (Path(fixture) / DIRECTORY.decode() / "s").exists()}
            recovery_command = [str(recovery_binary or binary), *command[1:]]
            recovered = subprocess.run(recovery_command, env=environment, stdout=log,
                                       stderr=subprocess.STDOUT, timeout=30)
        result = {"phase": phase, "injected_signal": "SIGKILL", "event": event,
                  "crashed_child_exit": process.returncode,
                  "before_recovery": before, "recovery_exit": recovered.returncode,
                  "public_socket_after": (Path(fixture) / "s").exists(),
                  "staged_socket_after": (Path(fixture) / DIRECTORY.decode() / "s").exists(),
                  "elapsed_seconds": round(time.monotonic() - started, 3)}
        result["pass"] = (recovered.returncode == 0 and not result["public_socket_after"]
                          and not result["staged_socket_after"])
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--phase", choices=["created", "claimed", "bound", "prepared", "renamed", "committed", "legacy_ready"])
    parser.add_argument("--recovery-binary", type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("qualification requires native Linux x86_64")
    binary = args.binary.resolve(strict=True)
    recovery_binary = (args.recovery_binary or binary).resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"command": [str(binary), "--ignored", "--exact", DRIVER, "--nocapture"],
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "recovery_binary": str(recovery_binary),
              "recovery_binary_sha256": hashlib.sha256(recovery_binary.read_bytes()).hexdigest(),
              "host_os": platform.platform(), "kernel": platform.release(),
              "architecture": platform.machine(), "cases": []}
    phases = [args.phase] if args.phase else ["created", "claimed", "bound", "prepared", "renamed", "committed"]
    try:
        for phase in phases:
            result = run_case(binary, phase, args.output, recovery_binary)
            report["cases"].append(result)
            print(json.dumps(result), flush=True)
            if not result["pass"]:
                return 1
        return 0
    finally:
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
