"""MinerSentry - a behavioral cryptominer detector for Windows and Linux.

Detects CPU/GPU mining malware by the work it has to do, so recompiled,
packed, renamed or process-injected miners still show up where a signature
scanner misses them. It also reads the autostart and persistence locations a
miner uses to come back after a reboot, and the defences it tampers with.
"""

__version__ = "1.0.1"
__app_name__ = "MinerSentry"
