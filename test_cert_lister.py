import pytest
import ssl
import socket
from src.cert_lister import (
CertLister)


class TestCertLister:
    """
    A test suite for the cert_lister.py script, using pytest.
    """

    def test_create_connection(self):
        """
        Test that create_connection returns a socket object.
        """
        hostname = "google.com"
        sock = create_connection(hostname)
        assert isinstance(sock, socket.socket)
        sock.close()

    def test_wrap_connection(self):
        """
        Test that wrap_connection returns an SSLSocket object.
        """
        hostname = "google.com"
        sock = create_connection(hostname)
        ssl_sock = wrap_connection(sock, hostname)
        assert isinstance(ssl_sock, ssl.SSLSocket)
        ssl_sock.close()
        sock.close()

    def test_verify_cert(self):
        """
        Test that verify_cert returns a tuple.
        """
        hostname = "google.com"
        not_before, not_after, serial, issuer = verify_cert(hostname)
        assert isinstance(not_before, str)
        assert isinstance(not_after, str)
        assert isinstance(serial, str)
        assert isinstance(issuer, str)

    def test_parse_issuer(self):
        """
        Test that parse_issuer returns a string.
        """
        issuer_tuple = ((('countryName', 'US'),), (('stateOrProvinceName', 'California'),), ((
            'localityName', 'Mountain View'),), (('organizationName', 'Google LLC'),), (('commonName', 'www.google.com'),))
        issuer_string = parse_issuer(issuer_tuple)
        assert isinstance(issuer_string, str)

    def test_generate_cert_list(self):
        """Test generate_cert_list returns a list of dictionaries."""
        hosts = ["google.com", "example.com"]
        cert_list = generate_cert_list(hosts)
        assert isinstance(cert_list, list)
        assert isinstance(cert_list[0], dict)
