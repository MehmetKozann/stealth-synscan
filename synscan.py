#!/usr/bin/env python3
# synscan.py — stealth half-open scanner entry point.
#
# Usage:
#   sudo python3 synscan.py 1.2.3.4 -p 22,80,443 --rate 5
#   sudo python3 synscan.py 1.2.3.4 -p 1-1024 --rate 8 --decoy RND:4
#   sudo python3 synscan.py 1.2.3.4 -p 22,80,443 --confirm --banner --out output.json
#   sudo python3 synscan.py targets.txt -p 80,443 --rate 3
#   sudo python3 synscan.py 1.2.3.4 --resume .synscan_state.json

from synscan.cli import main

if __name__ == "__main__":
    main()
