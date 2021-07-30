import pytest

from webprobe import WebProbe


@pytest.fixture
def sample_domains():
    return "/home/eonraider/Dropbox/offensive-python/tools/web-probe/tests/" \
           "sample_files/amass-uber.com.txt"


@pytest.fixture
def dummy_targets():
    return ["invalid-domain.xyz", "google.com", "scanme.nmap.org",
            "hackthissite.org", "www.mibs-challenges.de", "demo.testfire.net"]


class TestWebProbe:
    def test_probe_instantiates_correctly(self, dummy_targets):
        """
        GIVEN a set of target domains and ports
        WHEN this set is passed as arguments to the initializer of the
            WebProbe class
        THEN an instance of WebProbe must be created without errors
        """

        probe = WebProbe(targets=dummy_targets)
        assert isinstance(probe.targets, list)
        assert probe.ports == [80, 443]
        assert probe.timeout == 10

    def test_probe_iterable_targets(self, dummy_targets):
        """
        GIVEN an instance of WebProbe
        WHEN this instance is set to execute on a given iterable of
            targets
        THEN the results must be returned without errors
        """

        probe = WebProbe(targets=dummy_targets)
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
        GIVEN an instance of WebProbe
        WHEN this instance is set to execute on a specific port number
        THEN the results must be returned without errors
        """

        probe = WebProbe(targets=dummy_targets, ports=443)
        for result in probe.execute():
            assert result in ['https://google.com',
                              'https://www.mibs-challenges.de',
                              'https://demo.testfire.net',
                              'https://hackthissite.org']

    def test_probe_single_target(self, dummy_targets):
        """
        GIVEN an instance of WebProbe
        WHEN this instance is set to execute on a specific domain and
            port number
        THEN the results must be returned without errors
        """

        probe = WebProbe(targets=dummy_targets[1], ports=443)
        assert "https://google.com" in probe.execute()

    def test_probe_prefer_https(self, dummy_targets):
        """
        GIVEN an instance of WebProbe
        WHEN this instance is set to execute on a given iterable of
            targets and prefer HTTPS responses
        THEN the results must be returned without errors
        """
        probe = WebProbe(targets=dummy_targets, prefer_https=True)
        for result in probe.execute():
            assert result in ['https://google.com',
                              'https://www.mibs-challenges.de',
                              'http://scanme.nmap.org',
                              'https://demo.testfire.net',
                              'https://hackthissite.org']

    def test_probe_from_file(self, sample_domains):
        """
        GIVEN an instance of WebProbe
        WHEN this instance is set to execute on a given set of targets
            correctly defined as line-separated strings on a text file
        THEN the results must be returned without errors
        """

        probe = WebProbe(targets=sample_domains, prefer_https=True)
        for result in probe.execute():
            assert "uber.com" in result
