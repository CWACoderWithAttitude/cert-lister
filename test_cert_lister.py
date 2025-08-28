import pytest
import ssl
import socket
from src.cert_lister import CertLister, parse_issuer


@pytest.fixture
def cert_lister_instance(tmp_path):
    """Pytest fixture to create a CertLister instance for tests."""
    # Create a dummy hosts file
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("google.com\nexample.com")
    # The CertLister reads hosts from this file on init
    return CertLister(filename=str(hosts_file))


class TestCertLister:
    """
    A test suite for the cert_lister.py script, using pytest.
    """

    def test_read_hostnames(self, cert_lister_instance):
        """
        Test that read_hostnames returns a list of hostnames.
        """
        hostnames = cert_lister_instance.read_hostnames()
        assert isinstance(hostnames, list)
        assert len(hostnames) == 2
        assert hostnames[0] == "google.com"
        assert hostnames[1] == "example.com"

    def test_read_real_hostnames(self, cert_lister_instance):
        """
        Test that read_hostnames returns a list of hostnames.
        """
        cert_lister_instance = CertLister(filename=str('./hostnames.txt'))
        hostnames = cert_lister_instance.read_hostnames()
        assert isinstance(hostnames, list)
        assert len(hostnames) == 8
        assert hostnames[0] == "www.denic.de"
        assert hostnames[7] == "www.intel.com"

    def test_create_connection(self, cert_lister_instance):
        """
        Test that create_connection returns a socket object.
        """
        hostname = "google.com"
        sock = cert_lister_instance.create_connection(hostname)
        assert isinstance(sock, socket.socket)
        sock.close()

    def test_wrap_connection(self, cert_lister_instance):
        """
        Test that wrap_connection returns an SSLSocket object.
        """
        hostname = "google.com"
        sock = cert_lister_instance.create_connection(hostname)
        ssl_sock = cert_lister_instance.wrap_connection(sock, hostname)
        assert isinstance(ssl_sock, ssl.SSLSocket)
        ssl_sock.close()
        sock.close()

    def test_verify_cert(self, cert_lister_instance):
        """
        Test that verify_cert returns a tuple.
        """
        hostname = "google.com"
        not_before, not_after, serial, issuer = cert_lister_instance.verify_cert(
            hostname)
        assert isinstance(not_before, str)
        assert isinstance(not_after, str)
        assert isinstance(serial, str)
        assert isinstance(issuer, str)
        assert issuer == 'countryName=US, organizationName=Google Trust Services, commonName=WE2'
        assert not_before == 'Aug 11 19:21:22 2025 GMT'
        assert not_after == 'Nov  3 19:21:21 2025 GMT'
        assert serial == '218CABF13C3DF1700A08868EC635270D'

    def test_get_host_connect_info_simple(self, cert_lister_instance):
        host, port = cert_lister_instance.get_host_connect_info(
            "google.com")
        assert host == "google.com"
        assert port == 443

    def test_get_host_connect_info_with_std_port(self, cert_lister_instance):
        host, port = cert_lister_instance.get_host_connect_info(
            "google.com:443")
        assert host == "google.com"
        assert port == 443

    def test_get_host_connect_info_with_non_std_port(self, cert_lister_instance):
        host, port = cert_lister_instance.get_host_connect_info(
            "google.com:8443")
        assert host == "google.com"
        assert port == 8443

    def test_verify_cert_hostname_has_port(self, cert_lister_instance):
        """
        Test that verify_cert returns a tuple.
        """
        hostname = "google.com"
        not_before, not_after, serial, issuer = cert_lister_instance.verify_cert(
            hostname)
        assert isinstance(not_before, str)
        assert isinstance(not_after, str)
        assert isinstance(serial, str)
        assert isinstance(issuer, str)
        assert issuer == 'countryName=US, organizationName=Google Trust Services, commonName=WE2'
        assert not_before == 'Aug 11 19:21:22 2025 GMT'
        assert not_after == 'Nov  3 19:21:21 2025 GMT'
        assert serial == '218CABF13C3DF1700A08868EC635270D'

    def test_parse_issuer(self):
        """
        Test that parse_issuer returns a string.
        """
        issuer_tuple = (
            (('countryName', 'US'),),
            (('organizationName', 'Google Trust Services LLC'),),
            (('commonName', 'GTS CA 1P5'),)
        )
        issuer_string = parse_issuer(issuer_tuple)
        assert isinstance(issuer_string, str)
        assert issuer_string == "countryName=US, organizationName=Google Trust Services LLC, commonName=GTS CA 1P5"

    def test_generate_cert_list_method(self, cert_lister_instance):
        """Test the generate_cert_list method populates cert_list."""
        hosts = ["google.com", "example.com"]
        cert_lister_instance.generate_cert_list(hosts)
        cert_list = cert_lister_instance.cert_list
        assert isinstance(cert_list, list)
        assert len(cert_list) == 2
        assert isinstance(cert_list[0], dict)
        assert cert_list[0]['host'] == 'google.com'
        assert cert_list[1]['host'] == 'example.com'
