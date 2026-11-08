"""Explicit IPv4 LAN sharing while retaining the original localhost listener."""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import threading

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / '.local/active_demo/lan.json'
PRIVATE_RANGES = tuple(ipaddress.ip_network(value) for value in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))


def lan_network(address, subnet):
    ip, network = ipaddress.ip_address(address), ipaddress.ip_network(subnet, strict=True)
    if (ip.version != 4 or network.version != 4 or ip not in network
            or ip in (network.network_address,network.broadcast_address)
            or not any(network.subnet_of(block) for block in PRIVATE_RANGES)):
        raise ValueError('LAN access requires an explicit private IPv4 address and its local subnet')
    return network


@dataclass(frozen=True)
class LanSettings:
    address: str
    subnet: str
    port: int
    certificate: Path
    private_key: Path
    trust_certificate: Path | None = None

    @classmethod
    def load(cls, path=CONFIG, *, check_address=True):
        if not Path(path).is_file():
            raise ValueError('LAN is not prepared. Run scripts/Prepare-LanAccess.ps1 first')
        row = json.loads(Path(path).read_text(encoding='utf-8'))
        if row.get('schema') != 'iris-lan-v1':
            raise ValueError('Unsupported LAN configuration')
        lan_network(row['address'],row['subnet'])
        if type(row['port']) is not int or not 1 <= row['port'] <= 65535:
            raise ValueError('Invalid LAN port')
        certificate, key = ROOT / row['certificate'], ROOT / row['private_key']
        if hashlib.sha256(certificate.read_bytes()).hexdigest() != row['certificate_sha256']:
            raise ValueError('LAN certificate does not match the prepared certificate')
        trust = ROOT / row.get('trust_certificate',row['certificate'])
        if hashlib.sha256(trust.read_bytes()).hexdigest() != row.get('trust_certificate_sha256',row['certificate_sha256']):
            raise ValueError('LAN trust certificate does not match the prepared authority')
        if check_address:
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
                    probe.bind((row['address'],0))
            except OSError as exc:
                raise ValueError('The configured LAN address is no longer on this PC. Run Prepare-LanAccess.ps1 again') from exc
        return cls(row['address'],row['subnet'],row['port'],certificate,key,trust)


@contextmanager
def lan_listener(settings, engine, tls_context, auth):
    if settings is None:
        yield None
        return
    from .server import DemoServer
    with DemoServer((settings.address,settings.port),engine,tls_context=tls_context,auth=auth,
                    allowed_subnet=settings.subnet) as server:
        worker = threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.25},daemon=True)
        worker.start()
        try:
            yield server
        finally:
            server.shutdown()
            worker.join(5)
