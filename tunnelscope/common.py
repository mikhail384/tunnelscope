import hashlib
import ipaddress
import json
import socket
import struct
import time


def uid(source, identity):
    return source + ':' + hashlib.sha256(str(identity).encode()).hexdigest()[:20]


def domain(value):
    value = str(value or '').strip().lower().rstrip('.')
    if len(value) > 253 or not value or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-_:' for c in value):
        return ''
    try:
        ipaddress.ip_address(value)
        return ''
    except ValueError:
        return value if '.' in value else ''


def ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ''


def dns_name(data, start, depth=0):
    if depth > 12:
        raise ValueError('dns pointer loop')
    parts, pos, end = [], start, None
    for _ in range(128):
        n = data[pos]
        if n & 192 == 192:
            ptr = ((n & 63) << 8) | data[pos + 1]
            suffix, _ = dns_name(data, ptr, depth + 1)
            parts.append(suffix)
            end = pos + 2
            break
        if n == 0:
            end = pos + 1
            break
        if n > 63:
            raise ValueError('bad dns label')
        parts.append(data[pos + 1:pos + n + 1].decode('ascii'))
        pos += n + 1
    if end is None:
        raise ValueError('bad dns name')
    return '.'.join(parts), end


def dns_answers(data):
    """Return unencrypted DNS answers only; no attribution from queries alone."""
    try:
        if len(data) < 12 or not data[2] & 128:
            return []
        qd, an = struct.unpack('!HH', data[4:8])
        pos, questions = 12, []
        for _ in range(min(qd, 16)):
            name, pos = dns_name(data, pos)
            questions.append(domain(name))
            pos += 4
        answers = []
        for _ in range(min(an, 64)):
            name, pos = dns_name(data, pos)
            kind, cls, ttl, size = struct.unpack('!HHIH', data[pos:pos + 10])
            pos += 10
            raw = data[pos:pos + size]
            pos += size
            if cls == 1 and ((kind == 1 and size == 4) or (kind == 28 and size == 16)):
                addr = socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6, raw)
                answers.append((addr, next((q for q in questions if q), domain(name)), min(ttl, 3600)))
        return answers
    except (ValueError, IndexError, UnicodeError, struct.error, OSError):
        return []


def tls_sni(data):
    """Parse a TLS ClientHello, including one spanning TLS records; no decryption."""
    try:
        handshake, pos = bytearray(), 0
        while pos + 5 <= len(data) and data[pos] == 22:
            size = int.from_bytes(data[pos + 3:pos + 5], 'big')
            if pos + 5 + size > len(data):
                return ''
            handshake.extend(data[pos + 5:pos + 5 + size])
            pos += 5 + size
        if len(handshake) < 4 or handshake[0] != 1:
            return ''
        if len(handshake) < int.from_bytes(handshake[1:4], 'big') + 4:
            return ''
        p = 38
        p += 1 + handshake[p]
        p += 2 + int.from_bytes(handshake[p:p + 2], 'big')
        p += 1 + handshake[p]
        end = p + 2 + int.from_bytes(handshake[p:p + 2], 'big')
        p += 2
        while p + 4 <= min(end, len(handshake)):
            typ, size = struct.unpack('!HH', handshake[p:p + 4])
            p += 4
            if typ == 0:
                q, stop = p + 2, p + size
                while q + 3 <= stop:
                    n = int.from_bytes(handshake[q + 1:q + 3], 'big')
                    if handshake[q] == 0:
                        return domain(bytes(handshake[q + 3:q + 3 + n]).decode('ascii'))
                    q += 3 + n
            p += size
    except (IndexError, ValueError, struct.error, UnicodeError):
        pass
    return ''


def parse_ip(data):
    """AF_PACKET/SOCK_DGRAM starts at IP, for Ethernet and TUN devices alike."""
    try:
        version = data[0] >> 4
        if version == 4:
            offset, proto = (data[0] & 15) * 4, data[9]
            if offset < 20 or int.from_bytes(data[6:8], 'big') & 0x1fff:
                return None
            src, dst = socket.inet_ntop(socket.AF_INET, data[12:16]), socket.inet_ntop(socket.AF_INET, data[16:20])
            size = int.from_bytes(data[2:4], 'big')
        elif version == 6:
            offset, proto, size = 40, data[6], 40 + int.from_bytes(data[4:6], 'big')
            src, dst = socket.inet_ntop(socket.AF_INET6, data[8:24]), socket.inet_ntop(socket.AF_INET6, data[24:40])
            for _ in range(8):
                if proto in (0, 43, 60):
                    proto, offset = data[offset], offset + (data[offset + 1] + 1) * 8
                elif proto == 44:
                    if int.from_bytes(data[offset + 2:offset + 4], 'big') & 0xfff8:
                        return None
                    proto, offset = data[offset], offset + 8
                else:
                    break
        else:
            return None
        if proto not in (6, 17):
            return None
        sport, dport = struct.unpack('!HH', data[offset:offset + 4])
        seq, flags = 0, 0
        if proto == 6:
            seq = int.from_bytes(data[offset + 4:offset + 8], 'big')
            flags = data[offset + 13]
            hlen = (data[offset + 12] >> 4) * 4
            if hlen < 20:
                return None
        else:
            hlen = 8
        return {'src':src, 'dst':dst, 'sport':sport, 'dport':dport, 'protocol':'TCP' if proto == 6 else 'UDP',
                'size':size, 'seq':seq, 'flags':flags, 'payload':data[offset + hlen:min(size, len(data))]}
    except (IndexError, ValueError, OSError, struct.error):
        return None


def http_host(payload):
    if payload[:4] not in (b'GET ', b'POST', b'HEAD', b'PUT ', b'OPTI', b'DELE', b'PATC'):
        return ''
    for line in payload[:8192].split(b'\r\n'):
        if line.lower().startswith(b'host:'):
            return domain(line[5:].decode('ascii', 'ignore').strip().split(':')[0])
    return ''
