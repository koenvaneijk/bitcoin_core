"""
bitcoin_core.py - Pure Python module for interacting with a Bitcoin Core node
Author: Koen van Eijk <vaneijk.koen@gmail.com>
Licensed under AGPLv3
"""
import json
import logging
import os
import platform
import urllib.error
import urllib.request
from base64 import b64encode
from typing import Any, Dict


class JsonRpcClient:
    def __init__(self, url: str, rpc_user: str, rpc_password: str) -> None:
        self.url = url
        self.headers: Dict[str, str] = {"content-type": "application/json"}
        self.auth: str = b64encode(f"{rpc_user}:{rpc_password}".encode()).decode()

    def call(self, method: str, *params: Any) -> Any:
        data: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }
        req: urllib.request.Request = urllib.request.Request(
            self.url, json.dumps(data).encode(), headers=self.headers
        )
        req.add_header("Authorization", f"Basic {self.auth}")
        try:
            response: str = urllib.request.urlopen(req).read().decode()
        except urllib.error.HTTPError as e:
            raise Exception(e.reason)
        result: Dict[str, Any] = json.loads(response)

        if result.get("error"):
            raise Exception(result["error"]["message"])
        else:
            return result["result"]
        
class Client:
    def __init__(self, network="", rpc_client=None):
        self.network = network
        self.logger = logging.getLogger(__name__)

        if rpc_client is None:
            rpc_user, rpc_password = self.read_cookie()
            if self.network == "regtest":
                url = "http://localhost:18443"
            elif self.network == "testnet":
                url = "http://localhost:18332"
            else:
                url = "http://localhost:8332"
            rpc_client = JsonRpcClient(
                url=url,
                rpc_user=rpc_user,
                rpc_password=rpc_password,
            )
        self.rpc_client = rpc_client

        self.test_connection()

    def get_data_dir(self):
        system = platform.system()
        if system == "Windows":
            return os.path.join(os.environ["APPDATA"], "Bitcoin")
        elif system == "Linux":
            return os.path.expanduser("~/.bitcoin")
        elif system == "Darwin":  # Mac OSX
            return os.path.expanduser("~/Library/Application Support/Bitcoin")
        else:
            raise Exception("Unsupported operating system: {}".format(system))

    def read_cookie(self):
        data_dir = self.get_data_dir()
        if self.network == "regtest":
            data_dir = os.path.join(data_dir, "regtest")
        cookie_file = os.path.join(data_dir, ".cookie")
        if not os.path.exists(cookie_file):
            raise Exception("Cookie file not found at: {}".format(cookie_file))

        with open(cookie_file, "r") as f:
            content = f.read()

        rpc_user, rpc_password = content.split(":")
        return rpc_user, rpc_password

    def test_connection(self):
        result = self.rpc_client.call("getblockchaininfo")
        self.logger.info(f"Test connection successful. Result: {result}")
        return result

    def get_new_address(self):
        result = self.rpc_client.call("getnewaddress")
        self.logger.info(f"New address generated. Result: {result}")
        return result

    def get_balance(self):
        result = self.rpc_client.call("getbalance")
        self.logger.info(f"Balance retrieved. Result: {result}")
        return result

    def send_to_address(self, address, amount):
        result = self.rpc_client.call("sendtoaddress", address, amount)
        self.logger.info(f"Sent {amount} to {address}. Result: {result}")
        return result

    def create_raw_transaction(self, inputs, outputs):
        result = self.rpc_client.call("createrawtransaction", inputs, outputs)
        self.logger.info(f"Raw transaction created. Result: {result}")
        return result

    def decode_raw_transaction(self, raw_tx):
        result = self.rpc_client.call("decoderawtransaction", raw_tx)
        self.logger.info(f"Raw transaction decoded. Result: {result}")
        return result

    def get_raw_transaction(self, txid, verbose=False):
        result = self.rpc_client.call("getrawtransaction", txid, verbose)
        self.logger.info(f"Raw transaction retrieved. Result: {result}")
        return result

    def get_transaction(self, txid):
        result = self.rpc_client.call("gettransaction", txid)
        self.logger.info(f"Transaction retrieved. Result: {result}")
        return result

    def extract_opreturn_data(self, decoded_tx):
        for output in decoded_tx["vout"]:
            if output["scriptPubKey"]["type"] == "nulldata":
                result = output["scriptPubKey"]["asm"].split(" ")[1]
                self.logger.info(f"OP_RETURN data extracted. Result: {result}")
                return result
        else:
            result = ""
            self.logger.info("No OP_RETURN data found.")
            return result

    def decode_opreturn_data(self, data):
        result = bytes.fromhex(data).decode("utf-8")
        self.logger.info(f"OP_RETURN data decoded. Result: {result}")
        return result

    def sign_raw_transaction_with_wallet(self, raw_tx):
        result = self.rpc_client.call("signrawtransactionwithwallet", raw_tx)
        self.logger.info(f"Raw transaction signed with wallet. Result: {result}")
        return result

    def send_raw_transaction(self, raw_tx):
        result = self.rpc_client.call("sendrawtransaction", raw_tx)
        self.logger.info(f"Raw transaction sent. Result: {result}")
        return result

    def get_block_count(self):
        result = self.rpc_client.call("getblockcount")
        self.logger.info(f"Block count retrieved. Result: {result}")
        return result

    def get_block_hash(self, block_height):
        result = self.rpc_client.call("getblockhash", block_height)
        self.logger.info(f"Block hash retrieved. Result: {result}")
        return result

    def get_block(self, block_hash):
        result = self.rpc_client.call("getblock", block_hash)
        self.logger.info(f"Block retrieved. Result: {result}")
        return result

    def get_block_header(self, block_hash):
        result = self.rpc_client.call("getblockheader", block_hash)
        self.logger.info(f"Block header retrieved. Result: {result}")
        return result

    def get_mempool_info(self):
        result = self.rpc_client.call("getmempoolinfo")
        self.logger.info(f"Mempool info retrieved. Result: {result}")
        return result

    def get_raw_mempool(self, verbose=False):
        result = self.rpc_client.call("getrawmempool", verbose)
        self.logger.info(f"Raw mempool retrieved. Result: {result}")
        return result

    def get_mempool_entry(self, txid):
        result = self.rpc_client.call("getmempoolentry", txid)
        self.logger.info(f"Mempool entry retrieved. Result: {result}")
        return result

    def get_raw_change_address(self):
        result = self.rpc_client.call("getrawchangeaddress")
        self.logger.info(f"Raw change address retrieved. Result: {result}")
        return result

    def listunspent(self, minconf=1, maxconf=9999999, addresses=[]):
        result = self.rpc_client.call("listunspent", minconf, maxconf, addresses)
        self.logger.info(f"Unspent transactions retrieved. Result: {result}")
        return result

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    client = Client(network="regtest")

    address = client.get_new_address()
    txid = client.send_to_address(address, 1000)
    raw_tx = client.create_raw_transaction(
        [{"txid": txid, "vout": 0}],
        {address: 999, "data": "Hello world!".encode("utf-8").hex()},
    )
    signed_tx = client.sign_raw_transaction_with_wallet(raw_tx)
    decoded_tx = client.decode_raw_transaction(raw_tx)
    op_return_data = client.extract_opreturn_data(decoded_tx)
    decoded_op_return_data = client.decode_opreturn_data(op_return_data)

    unspent = client.listunspent()