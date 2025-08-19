# cert_lister.py
import ssl
import socket
import datetime
import csv
from rich import traceback
from rich.console import Console
from rich.theme import Theme
from rich import print_json

my_theme = Theme({'error': 'bold red', 'warning': 'bold yellow'})
console = Console(theme=my_theme)
traceback.install()
SOCKET_TIMEOUT_SECONDS = 3


def create_connection(hostname: str) -> socket:
    """Create connection to the host with the cert you want to check.
    The global variable `SOCKET_TIMEOUT_SECONDS` hold the timeout setting for opening a socket

    Args:
        hostname (str): hostname to connect to

    Returns:
        socket: Open socket
    """
    return socket.create_connection((hostname, 443))  # , SOCKET_TIMEOUT_SECONDS)


def wrap_connection(socket, hostname: str) -> ssl.SSLSocket:
    ctx: ssl.SSLContext = ssl.create_default_context()
    return ctx.wrap_socket(socket, server_hostname=hostname)


def verify_cert(hostname: str) -> tuple[str, str, str, str]:
    """Fetch and verify a web servers certificate

    Args:
        hostname (str): Hstname to fetch the cert from

    Returns:
        tuple: Tuple with `notBefore` and `notAfter` fields from the cert.
    """
    # with socket.create_connection((hostname, 443), SOCKET_TIMEOUT_SECONDS) as sock:
    with create_connection(hostname) as sock:
        pass
        # with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
        with wrap_connection(sock, hostname=hostname) as ssock:
            version = ssock.version()

            # print(f"Version is : {version}")
            ssock.do_handshake()
            cert = ssock.getpeercert()
            # print(f"Cert is valid: {cert}")

            # notBefore, notAfte, issuer = extractDates(cert=cert)
            return extractDates(cert=cert)

# def parse_issuer(issuer_tuple):
#    """Convert issuer tuple to a readable string."""
#    return ", ".join(f"{k}={v}" for t in issuer_tuple for k, v in [t])


def parse_issuer(issuer_tuple: tuple):
    """Convert issuer tuple to a readable string."""
    return ", ".join(f"{k}={v}" for t in issuer_tuple for k, v in t)


def extractDates(cert: dict) -> tuple[str, str, str, str]:
    """Extract dates from a TLS cert.

    Args:
        cert (_type_): Cert to extract the information from

    Returns:
        _type_: Tuple with start and end date
    """
    notBefore = str(cert['notBefore'])
    notAfter = str(cert['notAfter'])
    issuer_tuple = cert['issuer']
    parsed = parse_issuer(issuer_tuple)
    issuer: str = parsed
    serial: str = str(cert['serialNumber'])

    return (notBefore, notAfter, serial, issuer)


def generate_cert_list(hosts: list[str]):
    """Generate a list of vaidity dates for hostnames and validity start and end date.

    Args:
        hosts (list[str]): List of strings. Each string has to be a valid hostname

    Returns:
        _list[dict[str, str]]_: list of dicts. Each dict hold hostname and the respective dates
    """
    data: list[dict[str, str,]] = []
    for host in hosts:
        notBefore, notAfter, serial, issuer = verify_cert(hostname=host)
        d: dict[str, str] = {'host': host,
                             'notBefore': notBefore,
                             'notAfter': notAfter,
                             'serial': serial,
                             'issuer': issuer}
        data.append(d)
    return data


def read_hostnames() -> list[str]:
    """Read hostnames to check from text file. Converts text-lines to list.

    Returns:
        list[str]: List of hostnames
    """
    filename = 'hostnames_denic.txt'
    with open(filename, 'r') as hostnames:
        hosts = hostnames.read().splitlines()
    return hosts


def export_list_to_file(info_list):
    """Write cert information to excel compatible csv file.
    Impress your manager ;-)

    Args:
        info_list (_type_): _description_
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    filename = f'/tmp/cert_dates_{timestamp}.csv'
    with open(filename, 'w', newline='') as csvfile:
        certwriter = csv.writer(csvfile, delimiter=',',
                                quotechar='"', quoting=csv.QUOTE_ALL)
        for item in info_list:
            certwriter.writerow(
                [item['host'], item['notBefore'], item['notAfter'], item['serial'], item['issuer']])


def main() -> None:
    hostnames = read_hostnames()
    print(hostnames)
    result = generate_cert_list(hostnames)
    # console.print(result, style="bold green")
    export_list_to_file(result)


if __name__ == "__main__":
    main()


#
# [PROMPT_SUGGESTION]How would I add better error handling to the cert_lister.py script?[/PROMPT_SUGGESTION]
# [PROMPT_SUGGESTION]Can you show me how to add certificate chain validation to the script?[/PROMPT_SUGGESTION]
# -->
