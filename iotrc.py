#!/usr/bin/env python3
"""
IO Tracer (macOS) - A macOS I/O tracing utility.

Entry point for the macOS IO Tracer, which traces file system and block-device
I/O operations on macOS using DTrace. It is the macOS counterpart of the Linux
io-tracer and produces the same on-disk trace format (see docs/TRACE_FORMAT.md),
so traces are comparable across operating systems.

Usage:
    sudo python3 iotrc.py [OPTIONS]
    sudo python3 iotrc.py dev [DEV OPTIONS]

Options:
    -v, --verbose             Print verbose output
    -a, --anonimize           Enable anonymization of process and file names
    --network                 Enable network event tracing — connection
                              lifecycle (socket/bind/listen/accept/connect/
                              shutdown). Off by default.
    --computer-id             Print this machine ID and exit
    --reward                  Show your reward code (unlocked after uploading)
    --no-upload               Disable automatic upload of traces (for testing)

Dev Options (only with the 'dev' subcommand):
    --trace-bucket NAME       Override upload bucket (default: mac_trace_v1_test)

Examples:
    sudo python3 iotrc.py
    sudo python3 iotrc.py --network -v
    sudo python3 iotrc.py dev --no-upload
    python3 iotrc.py --computer-id
"""

import argparse
import os
import platform
import resource
import shutil
import sys
import tempfile

from src.tracer.IOTracer import IOTracer
from src.utility.utils import capture_machine_id, get_reward_code


def maximize_fd_limit():
    """Attempt to maximize the file descriptor open limit."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 1048576
        if hard != resource.RLIM_INFINITY:
            target = min(target, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


if __name__ == "__main__":
    if platform.system() != "Darwin":
        print("Error: this is the macOS IO Tracer; run it on macOS. "
              "For Linux use io-tracer-linux.")
        sys.exit(1)

    if os.geteuid() != 0:
        print("Error: IO Tracer must be run with sudo or as root (DTrace requires it).")
        sys.exit(1)

    if shutil.which("dtrace") is None and not os.path.exists("/usr/sbin/dtrace"):
        print("Error: 'dtrace' was not found. DTrace ships with macOS; ensure it "
              "is available and that System Integrity Protection allows it.")
        sys.exit(1)

    maximize_fd_limit()
    app_version = "vRelease"

    parser = argparse.ArgumentParser(description="Trace macOS I/O operations with DTrace")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output")
    parser.add_argument("-a", "--anonimize", action="store_true", help="Enable anonymization of process and file names")
    parser.add_argument("--network", action="store_true", help="Enable network (connection lifecycle) tracing")
    parser.add_argument("--computer-id", action="store_true", help="Print this machine ID and exit")
    parser.add_argument("--reward", action="store_true", help="Show your reward code (unlocked after uploading traces)")
    parser.add_argument("--no-upload", action="store_true", help="Disable automatic upload of traces (for testing)")

    subparsers = parser.add_subparsers(dest="subcommand")
    dev_parser = subparsers.add_parser("dev", help="Run in developer mode with extra logs and checks")
    dev_parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output")
    dev_parser.add_argument("-a", "--anonimize", action="store_true", help="Enable anonymization of process and file names")
    dev_parser.add_argument("--network", action="store_true", help="Enable network (connection lifecycle) tracing")
    dev_parser.add_argument("--no-upload", action="store_true", help="Disable automatic upload of traces (for testing)")
    dev_parser.add_argument("--trace-bucket", type=str, default=None, help="Override upload bucket name (default: mac_trace_v1_test)")

    parse_args = parser.parse_args()
    output_dir = tempfile.gettempdir()

    if parse_args.computer_id:
        print(f"Here is your computer ID: {capture_machine_id().upper()}")
        sys.exit(0)

    if parse_args.reward:
        reward_code = get_reward_code()
        if reward_code:
            print(f"Your Prolific submissions code: {reward_code}")
        else:
            print("Reward not yet unlocked. Upload at least one trace to complete your submission!")
        sys.exit(0)

    developer_mode = parse_args.subcommand == "dev"

    # Directory holding the bundled .d scripts, resolved relative to this file so
    # the tracer works regardless of the caller's working directory.
    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src", "tracer", "dtrace")

    tracer = IOTracer(
        output_dir=output_dir,
        script_dir=script_dir,
        automatic_upload=not parse_args.no_upload,
        developer_mode=developer_mode,
        version=app_version,
        anonymous=parse_args.anonimize,
        verbose=parse_args.verbose,
        trace_bucket=(parse_args.trace_bucket if developer_mode else None),
        trace_network=parse_args.network,
    )
    tracer.trace()
