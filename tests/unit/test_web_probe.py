import pytest

from webprobe import WebProbeProxy


@pytest.fixture
def sample_domains():
    return "/home/eonraider/Dropbox/offensive-python/tools/web-probe/tests/" \
           "support_files/amass-uber.com.txt"


@pytest.fixture
def dummy_targets():
    return ["invalid-domain.xyz", "google.com", "scanme.nmap.org",
            "hackthissite.org", "www.mibs-challenges.de", "demo.testfire.net"]


class TestWebProbeProxy:
    def test_probe_instantiates_correctly(self, dummy_targets):
        """
        GIVEN a set of target domains and ports
        WHEN this set is passed as arguments to the initializer of the
            WebProbeProxy class
        THEN an instance of WebProbeProxy must be created without errors
        """

        probe = WebProbeProxy(targets=dummy_targets)
        assert isinstance(probe.targets, list)
        assert probe.ports == [80, 443]
        assert probe.timeout == 5
        assert probe.prefer_https is False
        assert probe.port_mapping == {80: "http", 443: "https"}

        '''Updating the attributes of an instance of WebProbeProxy 
        must also update those of the composed WebProbe instance 
        without raising AttributeError'''
        probe.ports = [8080, 9090]
        assert probe.ports == probe.webprobe.ports
        probe.timeout = 10
        assert probe.timeout == probe.webprobe.timeout

    # noinspection PyTypeChecker
    def test_invalid_arguments(self):
        """
        GIVEN a set of invalid arguments for WebProbeProxy
        WHEN this set is passed as arguments to the initializer of the
            WebProbeProxy class
        THEN an exception for each case must be raised
        """

        '''Creating an instance of WebProbeProxy without specifying a 
        target address must raise an exception'''
        with pytest.raises(SystemExit) as e:
            WebProbeProxy(targets=None)
        assert "Cannot proceed without specifying at least one target IP " \
               "address or domain name" in e.value.args[0]

        '''Creating an instance of WebProbeProxy by specifying a file 
        to which the current user has no read access must raise an 
        exception'''
        no_read_file_path = "/etc/shadow"
        with pytest.raises(SystemExit) as e:
            WebProbeProxy(targets=no_read_file_path)
        assert f"Permission denied when reading the file " \
               f"{no_read_file_path}" in e.value.args[0]

    def test_probe_iterable_targets(self, dummy_targets):
        """
        GIVEN an instance of WebProbeProxy
        WHEN this instance is set to execute on a given iterable of
            targets
        THEN the results must be returned without errors
        """

        probe = WebProbeProxy(targets=dummy_targets)
        for result in probe.execute():
            assert result in ['http://google.com',
                              'https://google.com',
                              'https://www.mibs-challenges.de',
                              'http://scanme.nmap.org',
                              'http://www.mibs-challenges.de',
                              'https://demo.testfire.net',
                              'http://demo.testfire.net',
                              'http://hackthissite.org',
                              'https://hackthissite.org']

    def test_probe_integer_port(self, dummy_targets):
        """
        GIVEN an instance of WebProbeProxy
        WHEN this instance is set to execute on a specific port number
        THEN the results must be returned without errors
        """

        probe = WebProbeProxy(targets=dummy_targets, ports=443)
        for result in probe.execute():
            assert result in ['https://google.com',
                              'https://www.mibs-challenges.de',
                              'https://demo.testfire.net',
                              'https://hackthissite.org']

    def test_probe_single_target(self, dummy_targets):
        """
        GIVEN an instance of WebProbeProxy
        WHEN this instance is set to execute on a specific domain and
            port number
        THEN the results must be returned without errors
        """

        probe = WebProbeProxy(targets=dummy_targets[1], ports=443)
        assert "https://google.com" in probe.execute()

    def test_probe_prefer_https(self, dummy_targets):
        """
        GIVEN an instance of WebProbeProxy
        WHEN this instance is set to execute on a given iterable of
            targets and prefer HTTPS responses
        THEN the results must be returned without errors
        """

        probe = WebProbeProxy(targets=dummy_targets, prefer_https=True)
        for result in probe.execute():
            assert result in ['https://google.com',
                              'https://www.mibs-challenges.de',
                              'http://scanme.nmap.org',
                              'https://demo.testfire.net',
                              'https://hackthissite.org']

    @pytest.mark.skip()
    def test_probe_rebound_port(self, http_server):
        """
        GIVEN an instance of WebProbeProxy
        WHEN this instance is set to execute on target serving HTTP
            from a non-standard port
        THEN a new port mapping must be used to send and receive probes
            to this server without errors
        """
        probe = WebProbeProxy(targets="127.0.0.1", port_mapping={8000: "http"})
        results = probe.execute()
        assert "http://127.0.0.1" in results

    def test_probe_from_file(self, sample_domains):
        """
        GIVEN an instance of WebProbeProxy
        WHEN this instance is set to execute on a given set of targets
            correctly defined as line-separated strings on a text file
        THEN the results must be returned without errors
        """

        probe = WebProbeProxy(targets=sample_domains, prefer_https=True)
        for result in probe.execute():
            assert "uber.com" in result
