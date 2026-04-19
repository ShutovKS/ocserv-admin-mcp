#!/usr/bin/env python3
import json
import sys

mode = sys.argv[1] if len(sys.argv) > 1 else "unknown"

if mode == "validate":
    print("validation-ok")
elif mode == "reload":
    print("reload-ok")
elif mode == "show-users":
    print(json.dumps([{"name": "live-user"}]))
elif mode == "show-sessions":
    print(json.dumps([{"name": "live-user", "ip": "10.0.0.8"}]))
else:
    print(f"unsupported:{mode}", file=sys.stderr)
    raise SystemExit(1)
