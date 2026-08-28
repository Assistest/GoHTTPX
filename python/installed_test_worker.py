import asyncio
import json
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import gohttpx


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = self.headers.get("Cookie", "").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


async def check_async(endpoint):
    async with gohttpx.AsyncClient(cookies={"owner": "B"}) as client:
        assert (await client.get(endpoint)).text == "owner=B"


if __name__ == "__main__":
    assert Path(gohttpx.__file__).is_relative_to(Path(sys.prefix))
    assert shutil.which("go") is None
    target = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{target.server_port}"
    try:
        with gohttpx.Client(cookies={"owner": "A"}) as client:
            assert client.get(endpoint).text == "owner=A"
            asyncio.run(check_async(endpoint))
            assert client.get(endpoint).text == "owner=A"
        state = gohttpx.runtime_status()
        assert state["start_count"] == 1 and state["active_clients"] == 0
        print(json.dumps({**state, "module": gohttpx.__file__, "version": gohttpx.__version__}), flush=True)
        sys.stdin.readline()
    finally:
        target.shutdown()
        target.server_close()
        thread.join(5)
