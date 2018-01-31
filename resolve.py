import asyncio
import uvloop
import struct
import socket
import json
import traceback
import datetime
from protocol import Buffer

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


class AsyncSocket:
    def __init__(self, loop=None):
        if not loop:
            loop = asyncio.get_event_loop()
        self.s = socket.socket()
        self.s.setblocking(False)
        self.loop = loop

    async def connect(self, remote):
        await self.loop.sock_connect(self.s, remote)

    async def recv(self, length):
        return await self.loop.sock_recv(self.s, length)

    async def sendall(self, data):
        return await self.loop.sock_sendall(self.s, data)

    async def ensure_recv(self, length):
        buf = Buffer()
        while len(buf) < length:
            buf.write(await self.recv(length))
        return buf.read()



def get_fqdn_list(req):
    data = Buffer(req)
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
        data.discard(2*2)
    return fqdn_list


def need_proxy(fqdn_list, rules):
    for fqdn in fqdn_list:
        for rule in rules:
            if fqdn.rstrip(".").endswith(rule):
                print("0",fqdn_list)
                return False
    print("1",fqdn_list)
    return True


class UDPListenerProtocol(asyncio.Protocol):
    def __init__(self, cfg, loop, rules):
        self.cfg, self.loop, self.rules = cfg, loop, rules

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        print(f"UDP request from {addr}")
        fqdn_list = get_fqdn_list(data)
        self.loop.create_task(handle_request(self.loop, data, ClientConnection(self.transport, addr), self.cfg, need_proxy(fqdn_list, self.rules)))


class ClientConnection:
    def __init__(self, transport, addr=None):
        self.peer, self.addr = transport, addr

    def send_message(self, msg,truncate=-1):
        if self.addr:
            if truncate<=0:
                self.peer.sendto(msg, self.addr)
            else:
                truncated=bytearray(msg[:truncate])
                truncated[2]|=2
                self.peer.sendto(bytes(truncated),self.addr)
                print("Truncated",truncated[2])
            print("UDP response to",self.addr)
        else:
            self.peer.write(struct.pack("!H", len(msg)))
            self.peer.write(msg)

    def close(self):
        if not self.addr:
            self.peer.close()


async def handle_request(loop: asyncio.AbstractEventLoop, request, peer, config, use_proxy=True):
    remote = AsyncSocket(loop)
    parse_dns(request)
    try:
        if use_proxy:
            await remote.connect(config["proxy_addr"])
            await remote.sendall(b'\x05\x01\x00')
            resp = await remote.ensure_recv(2)
            assert resp == b'\x05\x00'
            await remote.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(config["remote_addr"][0]) + struct.pack("!H", config["remote_addr"][1]))
            kind = (await remote.ensure_recv(4))[3]
            if kind == 1:
                await remote.ensure_recv(4)
            elif kind == 3:
                length = (await remote.ensure_recv(1))[0]
                await remote.ensure_recv(length)
            elif kind == 4:
                await remote.ensure_recv(16)
            else:
                print("error", kind)
            await remote.ensure_recv(2)
        else:
            await remote.connect(config["direct_addr"])
        await remote.sendall(struct.pack("!H", len(request)))
        await remote.sendall(request)
        length = struct.unpack("!H", await remote.ensure_recv(2))[0]
        resp = await remote.ensure_recv(length)
        parse_dns(resp)
        peer.send_message(resp)
        peer.close()
    except Exception:
        with open("exc.txt","a") as f:
            f.write(datetime.datetime.now().isoformat()+"\n")
            f.write(traceback.format_exc())
            f.write("="*30+"\n")


def parse_ip(ip_string):
    ip, port = ip_string.split(":")
    port = int(port)
    return ip, port


class TCPListenerProtocol(asyncio.Protocol):
    def __init__(self, config, loop, rules):
        self.config, self.rules, self.loop = config, rules, loop

    def connection_made(self, transport):
        client_addr = transport.get_extra_info('peername')
        print(f'TCP request from {client_addr}')
        self.transport = transport
        self.buf = Buffer()
        self.msg_size = -1

    def data_received(self, data):
        self.buf.write(data)
        if self.msg_size == -1 and len(self.buf) >= 2:
            self.msg_size = self.buf.read_packed(">H")
        if self.msg_size != -1 and len(self.buf) >= self.msg_size:
            req = self.buf.read()
            fqdn_list = get_fqdn_list(req)
            self.loop.create_task(handle_request(self.loop, req, ClientConnection(self.transport), self.config, need_proxy(fqdn_list, self.rules)))


def main():
    config = json.load(open("config.json"))
    for k in ("local_addr", "proxy_addr", "remote_addr", "direct_addr"):
        config[k] = parse_ip(config[k])
    print(config)
    rules = [line.strip().rstrip(".") for line in open("rules") if line.strip()]
    print(rules)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(loop.create_server(lambda: TCPListenerProtocol(config, loop, rules), *config["local_addr"]))
    loop.run_until_complete(loop.create_datagram_endpoint(lambda: UDPListenerProtocol(config, loop, rules), config["local_addr"]))
    loop.run_forever()

if __name__=="__main__":
    main()
