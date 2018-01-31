import struct
import socket as _socket


def get_type_name(type_id):
    return {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA",
            29: "LOC", 33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG",
            47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 55: "HIP", 257: "CAA"}.get(type_id, str(type_id))


def get_class_name(cls):
    return {1: "IN", 2: "CS", 3: "CH", 4: "HS"}.get(cls, str(cls))


class Buffer:
    def __init__(self, data=None, keep=False):
        if data:
            self._buf = bytearray(data)
        else:
            self._buf = bytearray()
        self._pos, self._keep = 0, keep

    def write(self, data):
        self._buf += data

    def __len__(self):
        return len(self._buf) - self._pos

    def read(self, length=-1):
        if length <= 0:
            length = len(self)
        if length > len(self):
            raise IndexError(f"Tried to read {length} bytes, but buffer has only {len(self._buf)} bytes")
        data = bytes(self._buf[self._pos:self._pos + length])
        if not self._keep:
            self._buf = self._buf[self._pos + length:]
            self._pos = 0
        else:
            self._pos += length
        return data

    def discard(self, length):
        if length > len(self):
            raise IndexError(f"Tried to discard {length} bytes, but buffer has only {len(self._buf)} bytes")
        if not self._keep:
            self._buf = self._buf[self._pos + length:]
            self._pos = 0
        else:
            self._pos += length

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return repr(bytes(self._buf[self._pos:]))

    def read_octet(self):
        return self.read(1)[0]

    def __getitem__(self, item):
        return self._buf.__getitem__(item)

    def seek(self, pos, diff=False):
        if diff:
            self._pos += pos
        else:
            self._pos = pos

    def write_octet(self, octet):
        self.write(struct.pack("B", octet))

    def read_packed(self, fmt, unpack_simple=True):
        t = struct.unpack(fmt, self.read(struct.calcsize(fmt)))
        if len(t) == 1:
            return t[0]
        else:
            return t

    def write_packed(self, fmt, *data):
        self.write(struct.pack(fmt, *data))

    def tell(self):
        return self._pos

    def peek(self, length):
        return bytes(self._buf[self._pos:self._pos + length])


def parse_message(data):
    buf = Buffer(data, keep=True)
    idx = buf.read_packed(">H")
    qr, opcode, aa, tc, rd = unpack_octet(buf.read_octet(), (1, 4, 1, 1, 1))
    ra, z, rcode = unpack_octet(buf.read_octet(), (1, 3, 4))
    qdcount, ancount, nscount, arcount = buf.read_packed(">HHHH")
    qdlist, anlist, nslist, arlist = [], [], [], []
    for _ in range(qdcount):
        qdlist.append(_read_question(buf))
    for _ in range(ancount):
        anlist.append(_read_rr(buf))
    for _ in range(nscount):
        nslist.append(_read_rr(buf))
    for _ in range(arcount):
        arlist.append(_read_rr(buf))
    return Message(idx, qr, opcode, aa, tc, rd, ra, z, rcode, qdlist, anlist, nslist, arlist)


class Message:
    def __init__(self, idx=0, qr=0, opcode=0, aa=0, tc=0, rd=0, ra=0, z=0, rcode=0, qdlist=None, anlist=None, nslist=None, arlist=None):
        self.id = idx
        self.qr, self.opcode, self.aa, self.tc, self.rd = qr, opcode, aa, tc, rd
        self.ra, self.z, self.rcode = ra, z, rcode
        self.qdlist, self.anlist, self.nslist, self.arlist = qdlist or [], anlist or [], nslist or [], arlist or []

    def pack(self):
        buf = Buffer()
        buf.write(struct.pack(">H", self.id))
        buf.write_octet(pack_octet((self.qr, self.opcode, self.aa, self.tc, self.rd), (1, 4, 1, 1, 1)))
        buf.write_octet(pack_octet((self.ra, self.z, self.rcode), (1, 3, 4)))
        for l in (self.qdlist, self.anlist, self.nslist, self.arlist):
            buf.write_packed(">H", len(l))
        # TODO: repack question and RR.
        # TODO: implement DNS compression
        return buf.read()

    def __str__(self):
        return f'Message(id={self.id},qr={self.qr},opcode={self.opcode},tc={self.tc},q={self.qdlist},a={self.anlist})'


class Question:
    def __init__(self, qname, qtype, qclass):
        self.qname, self.qtype, self.qclass = qname, qtype, qclass

    def __str__(self):
        return f'Question(name="{self.qname}",type={get_type_name(self.qtype)},class={get_class_name(self.qclass)})'

    def __repr__(self):
        return str(self)


class RR:
    def __init__(self, name, typ, cls, ttl, rdata):
        self.name, self.type, self.cls, self.ttl, self.rdlen, self.rdata = name, typ, cls, ttl, len(rdata), rdata

    def __str__(self):
        return f'RR(name={repr(self.name)},type={get_type_name(self.type)},class={get_class_name(self.cls)},ttl={self.ttl},rdata={repr(self.rdata)})'

    def __repr__(self):
        return str(self)


def _read_question(buf):
    return Question(_read_labels(buf, concat=True), buf.read_packed(">H"), buf.read_packed(">H"))


def _read_labels(buf: Buffer, concat=False):
    pos = buf.tell()
    labels = []
    while True:
        label_length = buf.read_octet()
        pos += 1
        if label_length == 0:
            break
        if label_length >= 0b11000000:
            dest_pos = ((label_length & 0b00111111) << 8) + buf.read_octet()
            buf.seek(dest_pos)
            labels += _read_labels(buf)
            pos += 1
            break
        else:
            labels.append(buf.read(label_length).decode("ascii"))
            pos += label_length
    buf.seek(pos)
    if concat:
        return ".".join(labels) + "."
    else:
        return labels


def _read_rr(buf):
    fqdn = _read_labels(buf, concat=True)
    typ, cls, ttl, rdlen = buf.read_packed(">HHIH")
    if typ == 1:  # A
        rdata = _socket.inet_ntop(_socket.AF_INET, buf.read(rdlen))
    elif typ == 2:  # NS
        rdata = _read_labels(buf, concat=True)
    elif typ == 28:  # AAAA
        rdata = _socket.inet_ntop(_socket.AF_INET6, buf.read(rdlen))
    elif typ in (5, 39):  # CNAME,DNAME
        rdata = _read_labels(buf, concat=True)
    elif typ == 15:  # MX
        rdata = (buf.read_packed(">H"), _read_labels(buf, concat=True))
    elif typ == 6:  # SOA
        rdata = (_read_labels(buf, concat=True), _read_labels(buf, concat=True), *buf.read_packed(">IIIII"))
    else:
        rdata = buf.read(rdlen)
    return RR(fqdn, typ, cls, ttl, rdata)


def unpack_octet(octet, fmt):
    if octet > 255 or octet < 0:
        raise ValueError(f"Invalid octet {octet}")
    bitstring = bin(octet)[2:]
    bitstring = "0" * (8 - len(bitstring)) + bitstring
    values = []
    tmp = []
    pos = 0
    for group in fmt:
        for x in range(group):
            tmp.append(bitstring[pos])
            pos += 1
        values.append(int("".join(tmp), 2))
        tmp.clear()
    return values


def pack_octet(values, fmt):
    if len(values) != len(fmt):
        raise ValueError("Invalid fmt or values")
    bitstring = ''
    for value, length in zip(values, fmt):
        part = bin(value)[2:]
        part = "0" * (length - len(part)) + part
        bitstring += part
    octet = int(bitstring, 2)
    if not (0 <= octet <= 255):
        raise ValueError("Too much values to pack")
    return octet


if __name__ == "__main__":
    req = b'\xc7x\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x06zydiig\x04info\x00\x00\x0f\x00\x01\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x0c\x00\n\x00\x08\xcd\xfeXC\xaa\xd6>\x0f'
    resp = b'\xc7x\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x06zydiig\x04info\x00\x00\x0f\x00\x01\xc0\x0c\x00\x0f\x00\x01\x00\x008?\x00\t\x00\x05\x04mail\xc0\x0c\x00\x00)\x02\x00\x00\x00\x00\x00\x00\x00'
    parse_message(req)
    parse_message(resp)
