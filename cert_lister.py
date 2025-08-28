# cert_lister.py
import json
import ssl
import socket
import datetime
import csv
from rich import traceback
from rich.console import Console
from rich.theme import Theme
from rich import print_json


class CertLister:

    def __init__(self, filename: str):
        self.result = []
        self.cert_list = []
        self.input_filename = filename
        self.output_filename = "cert_out.json"
        # print(f"Input file: {self.input_filename}")
        self.hosts = self.read_hostnames()
        # self.result = []
        # print(f"hosst: {self.hosts}")

    def get_hosts(self) -> list[str]:
        return self.hosts

    def process_host_list(self):
        self.result = self.generate_cert_list(self.hosts)

    def read_hostnames(self) -> list[str]:
        """Read hostnames to check from text file. Converts text-lines to list.

        Returns:
            list[str]: List of hostnames
        """

        with open(self.input_filename, 'r') as hostnames:
            hosts = hostnames.read().splitlines()
        return hosts

    def write_cert_json(self) -> None:
        """Write Cert Details to JSON file for further processing

        """

        with open(self.output_filename, 'w') as certs:
            certs.writelines(json.dumps(self.cert_list))

    def generate_cert_list(self, hosts: list[str]):
        """Generate a list of vaidity dates for hostnames and validity start and end date.

        Args:
            hosts (list[str]): List of strings. Each string has to be a valid hostname

        Returns:
            _list[dict[str, str]]_: list of dicts. Each dict hold hostname and the respective dates
        """
        data: list[dict[str, str,]] = []
        for host in hosts:
            notBefore, notAfter, serial, issuer = self.verify_cert(
                hostname=host)
            d: dict[str, str] = {'host': host,
                                 'notBefore': notBefore,
                                 'notAfter': notAfter,
                                 'serial': serial,
                                 'issuer': issuer}
            data.append(d)
        self.cert_list = data
        # return data

    def get_host_connect_info(self, host_entry: str) -> tuple[str, int]:
        """Parses a host entry which may include a port.

        Args:
            host_entry (str): The host entry, e.g., "example.com" or "example.com:8443".

        Returns:
            tuple[str, int]: A tuple containing the hostname and the port number.
        """
        if ':' in host_entry:
            host, port_str = host_entry.split(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                # Default to 443 if port is not a valid integer
                port = 443
        else:
            host = host_entry
            port = 443
        return host, port

    def verify_cert(self, hostname: str) -> tuple[str, str, str, str]:
        """Fetch and verify a web servers certificate

        Args:
            hostname (str): Hstname to fetch the cert from

        Returns:
            tuple: Tuple with `notBefore` and `notAfter` fields from the cert.
        """
        # with socket.create_connection((hostname, 443), SOCKET_TIMEOUT_SECONDS) as sock:
        host, port = self.get_host_connect_info(hostname)
        with self.create_connection(host, port) as sock:
            # with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            with self.wrap_connection(sock, hostname=host) as ssock:
                version = ssock.version()

                # print(f"Version is : {version}")
                ssock.do_handshake()
                cert = ssock.getpeercert()
                # print(f"Cert is valid: {cert}")

                # notBefore, notAfte, issuer = extractDates(cert=cert)
                return extractDates(cert=cert)

    def create_connection(self, hostname: str, port: int = 443) -> socket:
        """Create connection to the host with the cert you want to check.
        The global variable `SOCKET_TIMEOUT_SECONDS` hold the timeout setting for opening a socket

        Args:
            hostname (str): hostname to connect to
            port (int): port to connect to. Defaults to 443.

        Returns:
            socket: Open socket
        """
        return socket.create_connection((hostname, port))  # , SOCKET_TIMEOUT_SECONDS)

    def wrap_connection(self, socket, hostname: str) -> ssl.SSLSocket:
        ctx: ssl.SSLContext = ssl.create_default_context()
        return ctx.wrap_socket(socket, server_hostname=hostname)

    def export_list_to_file(self, info_list):
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


# my_theme = Theme({'error': 'bold red', 'warning': 'bold yellow'})
# console = Console(theme=my_theme)
# traceback.install()
# SOCKET_TIMEOUT_SECONDS = 3


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


def main(filename: str) -> None:
    cert_lister = CertLister(filename=filename)
    # print(f"cert_lister: {cert_lister.hosts}")
    cert_lister.process_host_list()
    print(f"result: {cert_lister.cert_list}")
    cert_lister.write_cert_json()
    # export_list_to_file(result)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("inputfile")
    args = parser.parse_args()
    # print(args.inputfile)
    main(args.inputfile)

    # cert_lister.read_hostnames()
    # print(f"result: ${cert_lister.result}")
#
# [PROMPT_SUGGESTION]How would I add better error handling to the cert_lister.py script?[/PROMPT_SUGGESTION]
# [PROMPT_SUGGESTION]Can you show me how to add certificate chain validation to the script?[/PROMPT_SUGGESTION]
# -->
