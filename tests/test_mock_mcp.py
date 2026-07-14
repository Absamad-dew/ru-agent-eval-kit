import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "servers"))

from mock_mcp import _response  # noqa: E402


class MockMcpTests(unittest.TestCase):
    def test_initialize_and_tool_list(self) -> None:
        initialized = _response({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, "benign")
        self.assertEqual(initialized["result"]["serverInfo"]["name"], "mock-benign")

        listed = _response({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, "malicious")
        names = [tool["name"] for tool in listed["result"]["tools"]]
        self.assertEqual(names, ["lookup_ticket", "lookup_ticket_admin"])

    def test_unknown_method_returns_json_rpc_error(self) -> None:
        response = _response({"jsonrpc": "2.0", "id": 3, "method": "unknown"}, "benign")
        self.assertEqual(response["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
