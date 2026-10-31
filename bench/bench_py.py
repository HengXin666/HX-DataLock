"""Small repeatable timings for the v1 open path.

Usage: uv run python bench/bench_py.py
Default sizes stay small so the script finishes quickly. Pass sizes in bytes
as arguments to include a larger sample.
"""

from __future__ import annotations

import statistics
import sys
import time

from hx_datalock import create_keyring, make_user_data_lock

PASSWORD = "correct horse battery staple for hx datalock"


def median(samples: list[float]) -> float:
    return statistics.median(samples)


def main() -> None:
    sizes = [int(item) for item in sys.argv[1:]] or [64 * 1024, 256 * 1024]
    keyring = create_keyring(PASSWORD, scrypt_n=16384)
    user = make_user_data_lock(keyring, PASSWORD)
    for size in sizes:
        payload = bytes([size % 251]) * size
        user.lockBytes(payload[:1024])
        samples = []
        for _ in range(5):
            envelope = user.lockBytes(payload)
            started = time.perf_counter()
            opened = user.openBytes(envelope)
            samples.append((time.perf_counter() - started) * 1000)
            if opened != payload:
                raise SystemExit("openBytes mismatch")
        print(f"openBytes size={size} median_ms={median(samples):.2f} n={len(samples)}")


if __name__ == "__main__":
    main()
