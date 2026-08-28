import argparse
import json
import os
import sys
import time

import gohttpx
import _gohttpx_runtime


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--phase", default="running")
    args = parser.parse_args()
    gohttpx.configure_runtime(binary_path=args.binary)
    if args.phase == "spawned":
        original = _gohttpx_runtime.JobProcess

        class PausedProcess(original):
            def __init__(self, command):
                super().__init__(command)
                print(json.dumps({"child_pid": self.pid, "phase": "spawned"}), flush=True)
                time.sleep(60)

        _gohttpx_runtime.JobProcess = PausedProcess
    elif args.phase == "ready":
        original_probe = gohttpx._runtime._probe

        def paused_probe(instance):
            result = original_probe(instance)
            print(json.dumps({"child_pid": instance.process.pid, "phase": "ready"}), flush=True)
            time.sleep(60)
            return result

        gohttpx._runtime._probe = paused_probe
    with gohttpx.Client() as client:
        print(json.dumps(gohttpx.runtime_status()), flush=True)
        for line in sys.stdin:
            command = json.loads(line)
            if command["op"] == "exit":
                return
            if command["op"] == "abrupt":
                os._exit(23)
            if command["op"] == "exception":
                raise RuntimeError("test worker failure")
            if command["op"] == "request":
                response = client.get(command["url"])
                print(json.dumps({"status": response.status_code, "body": response.json()}), flush=True)
            elif command["op"] == "status":
                print(json.dumps(gohttpx.runtime_status()), flush=True)


if __name__ == "__main__":
    main()
