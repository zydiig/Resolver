# SPDX-License-Identifier: GPL-3.0-only

import curio
import struct
from curio import socket
import json
from protocol import Buffer, parse_message
from traceback import format_exc
from sys import exc_info, stderr
import logging
from argparse import ArgumentParser
import os


class Configuration:
    def __init__(self, config, logger, ruleset):
        self.config, self.logger, self.ruleset = config, logger, ruleset

    def __getitem__(self, item):
        return self.config.get(item)

    def __getattr__(self, item):
        return self.config.get(item)


def parse_ip(ip_string):
    ip, port = ip_string.split(":")
    return ip, int(port)


def need_proxy(request, rules):
    fqdn_list = get_fqdn_list(request)
    for fqdn in fqdn_list:
        for rule in rules:
            if fqdn.rstrip(".").endswith(rule):
                return False
    return True


def get_fqdn_list(request):
    data = Buffer(request)
    data.discard(4)
    qdcount = data.read_packed(">H")
    data.discard(2 * 3)
    fqdn_list = []
    for idx in range(qdcount):
        labels = []
        while True:
            label_length = data.read_octet()
            if label_length == 0:
                break
            else:
                labels.append(data.read(label_length).decode("ascii"))
        fqdn_list.append(".".join(labels) + ".")
        data.discard(2 * 2)
    return fqdn_list


class ExtendedSocket:
    _relayed = ("recv", "close", "sendall", "connect")

    def __init__(self, s=None):
        self.s = s if s else socket.socket()

    async def ensure_recv(self, length):
        data = bytearray()
        while len(data) < length:
            data += await self.s.recv(length - len(data))
        return bytes(data)

    async def recv_uint16be(self):
        return struct.unpack(">H", await self.ensure_recv(2))[0]

    def __getattr__(self, item):
        if item in self._relayed:
            return getattr(self.s, item)
        raise AttributeError(f"{item} does not exist")


async def resolve(config, request, use_proxy=True):
    config.logger.debug(str(parse_message(request)))
    remote = ExtendedSocket()
    if use_proxy:
        await remote.connect(config.proxy_addr)
        await remote.sendall(b'\x05\x01\x00')
        assert (await remote.ensure_recv(2)) == b'\x05\x00'
        await remote.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(config.remote_addr[0]) + struct.pack("!H", config["remote_addr"][1]))
        kind = (await remote.ensure_recv(4))[3]
        if kind == 1:
            await remote.ensure_recv(4)
        elif kind == 3:
            length = (await remote.ensure_recv(1))[0]
            await remote.ensure_recv(length)
        elif kind == 4:
            await remote.ensure_recv(16)
        else:
            raise ValueError(f'Invalid ADDR type {kind}')
        await remote.ensure_recv(2)
    else:
        await remote.connect(config.direct_addr)
    await remote.sendall(struct.pack(">H", len(request)))
    await remote.sendall(request)
    length = await remote.recv_uint16be()
    resp = await remote.ensure_recv(length)
    config.logger.debug(str(parse_message(resp)))
    return resp


def log_exception(config):
    exc = exc_info()
    if exc[0] == KeyboardInterrupt:
        return False
    elif exc[0] == curio.errors.TaskCancelled:
        return False
    config.logger.debug("\n" + format_exc())
    return True


async def handle_tcp_request(config, client, addr):
    try:
        client = ExtendedSocket(client)
        reqlen = await client.recv_uint16be()
        req = await client.ensure_recv(reqlen)
        resp = await resolve(config, req, use_proxy=need_proxy(req, config.ruleset))
        await client.sendall(struct.pack(">H", len(resp)))
        await client.sendall(resp)
        await client.close()
    except Exception:
        log_exception(config)


async def handle_udp_request(config, sock, req, addr):
    try:
        resp = await resolve(config, req, use_proxy=need_proxy(req, config.ruleset))
        config.logger.debug(f"UDP LEN {len(resp)}")
        await sock.sendto(resp, addr)
    except Exception:
        log_exception(config)


async def udp_listen(config):
    s = socket.socket(type=socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(config.local_addr)
    async with s:
        while True:
            try:
                req, addr = await s.recvfrom(10240)
                await curio.spawn(handle_udp_request, config, s, req, addr, daemon=True)
            except Exception:
                if not log_exception(config):
                    break


async def tcp_listen(config):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(config.local_addr)
    s.listen(10)
    async with s:
        while True:
            try:
                client, addr = await s.accept()
                await curio.spawn(handle_tcp_request, config, client, addr, daemon=True)
            except Exception:
                if not log_exception(config):
                    break


async def serve(config):
    async with curio.TaskGroup() as tg:
        await tg.spawn(tcp_listen(config))
        await tg.spawn(udp_listen(config))
        await tg.join()


def load_ruleset(filename):
    return [line.strip().rstrip(".") for line in open(filename) if line.strip()]


def main():
    parser = ArgumentParser()
    parser.add_argument("--laddr", "-l", help="Listening address", dest="local_addr")
    parser.add_argument("--raddr", "-r", help="DNS server to query through proxy", dest="remote_addr")
    parser.add_argument("--paddr", "-p", help="SOCKS proxy to use", dest="proxy_addr")
    parser.add_argument("--daddr", "-d", help="DNS server to query directly", dest="direct_addr")
    parser.add_argument("--config", "-c", help="Alternate configuration file to use")
    parser.add_argument("--rules", "-x", help="List of domains to query directly")
    parser.add_argument("--log-file", "-o", help="Pipe log to a disk file", default="resolver.log", dest="log_file")
    args = vars(parser.parse_args())
    if args["config"]:
        config = json.load(open(args.get("config")))
    elif os.path.exists("config.json"):
        config = json.load(open("config.json"))
    else:
        config = {}
    for k in ("local_addr", "proxy_addr", "remote_addr", "direct_addr"):
        if args[k]:
            config[k] = args[k]
        if k in config:
            config[k] = parse_ip(config[k])
        else:
            raise ValueError("Invalid configuration")
    if args["rules"]:
        ruleset = load_ruleset(filename=args.get("rules"))
    elif os.path.exists("rules"):
        ruleset = load_ruleset(filename="rules")
    elif "rules" in config:
        ruleset = config.get("rules")
    else:
        ruleset = []
    config["rules"] = ruleset
    logger = logging.getLogger("Resolver")
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(args["log_file"])
    stderr_handler = logging.StreamHandler(stderr)
    formatter = logging.Formatter("%(asctime)s:%(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(formatter)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stderr_handler)
    logger.info(repr(config))
    config["logger"] = logger
    config = Configuration(config, logger, ruleset)
    try:
        curio.run(serve, config)
    except KeyboardInterrupt:
        return
    except Exception:
        log_exception(config)


if __name__ == "__main__":
    main()
