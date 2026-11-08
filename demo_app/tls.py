"""Optional local HTTPS; certificate creation and OS trust are separate steps."""
from pathlib import Path
import ssl


def server_context(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    if not cert_file.is_file() or not key_file.is_file():
        raise ValueError('HTTPS certificate/key missing. Run scripts/New-LocalHttpsCertificate.ps1 first, '
                         'or provide --cert-file and --key-file. HTTPS will not fall back to HTTP.')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context
