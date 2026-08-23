"""Pet the hardware watchdog while a sentinel file exists.

The software guards did not survive the failure they were meant to
guard against: with 4 GB of RAM and 1.8 GB of zram, a big compile
thrashes compressed swap, which pins every core without ever tripping
the OOM killer. Nothing in userspace gets scheduled reliably enough to
repoint a symlink or issue a reboot, so a userspace watchdog is
petting nothing at exactly the moment it is needed.

The SoC's watchdog does not care. Arm it, pet it from here while the
test is healthy, and stop petting if this process cannot run -- the
board resets itself. On a clean finish the sentinel goes away and the
magic 'V' disarms it, which is the one thing that must not be skipped.
"""
import fcntl
import os
import struct
import sys
import time

WDIOC_SETTIMEOUT = 0xc0045706

def main():
  if len(sys.argv) < 3:
    sys.exit("usage: hw_watchdog.py <sentinel> <timeout_s>")
  sentinel, timeout = sys.argv[1], int(sys.argv[2])
  fd = os.open("/dev/watchdog", os.O_WRONLY)
  try:
    fcntl.ioctl(fd, WDIOC_SETTIMEOUT, struct.pack("i", timeout))
  except OSError:
    # Some drivers refuse to be reprogrammed. Their default is
    # still shorter than a wedged box stays wedged.
    pass
  # Pet on the driver's schedule, but check for the finish line every
  # second. Tying the two together means a clean run still holds the
  # watchdog armed for up to a third of its timeout after the work is
  # done, which reads exactly like a hang.
  interval = max(1, timeout // 3)
  last = 0.0
  while os.path.exists(sentinel):
    now = time.monotonic()
    if now - last >= interval:
      os.write(fd, b"\0")
      last = now
    time.sleep(1)
  os.write(fd, b"V")
  os.close(fd)

if __name__ == "__main__":
  main()
