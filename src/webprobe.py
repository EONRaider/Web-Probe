#!/usr/bin/env python3
# https://github.com/EONRaider/Web-Probe

__author__ = 'EONRaider @ keybase.io/eonraider'

import asyncio
import contextlib
from collections import defaultdict
from pathlib import Path
from typing import Collection, Coroutine, Iterator, Mapping, Union

import aiohttp


class WebProbe(object):
    def __init__(self, *,
                 targets: list[str],
                 ports: list[int],
                 timeout: Union[int, float],
                 prefer_https: bool,
                 fetch_headers: bool,
                 analyse_headers: bool,
                 port_mapping: Mapping):
        """Perform asynchronous TCP-connect scans on combinations of
        target IP addresses and/or domain names and port numbers.

        Args:
            targets (list[str]): A list of strings defining a sequence
                of IP addresses and/or domain names.
            ports (list[int]): A list of integers defining a sequence
                of valid port numbers as regulated by IETF RFC 6335.
            timeout (int, float): Time to wait for a response from a
                target before closing a connection to it. Setting this
                to too short an interval may prevent the scanner from
                waiting the time necessary to receive a valid response
                from a live server, generating a false-negative by
                identifying a result as a timeout too soon. Recommended
                setting to a minimum of 5 seconds.
            prefer_https (bool): Omit performing requests with the HTTP
                URI scheme for those servers that also respond with
                HTTPS.
            fetch_headers (bool): Fetch headers for each URL returned
                as valid by the probe.
            analyse_headers (bool): Perform a header analysis by
                fetching headers and writing a file displaying each
                header sorted by frequency in ascending order. Useful
                for finding unusual headers in request batches.
            port_mapping (Mapping): Allows ports other than 80 and 443
                to be assigned to HTTP and HTTPS, respectively. Ex:
                Dictionaries with the syntax {8080:'http'} or
                {8080:'http',9900:'https'}
        """

        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.prefer_https = prefer_https
        self.fetch_headers = fetch_headers
        self.analyse_headers = analyse_headers
        self.port_mapping = port_mapping
        self.results = list()
        self.headers = list()
        self.analysed_headers = dict()
        self.__loop = asyncio.get_event_loop()
        self.__observers = list()

    def _run_scan_tasks(self) -> list[Coroutine]:
        """Set up and run a scan coroutine for each combination of
        target domain and port number."""
        return [self._scan_target_port(target, port) for port in self.ports
                for target in self.targets]

    async def _run_fetch_headers(self) -> None:
        """Set up and run a coroutine that fetches the response headers
        for each URL returned from the probe as valid."""
        async with aiohttp.ClientSession(trust_env=True) as session:
            tasks = [asyncio.ensure_future(self._fetch_headers(session, url))
                     for url in self.results]
            self.headers = await asyncio.gather(*tasks)

    def register(self, observer) -> None:
        """Register a class that implements the interface of
        OutputMethod as an observer."""
        self.__observers.append(observer)

    async def _notify_all(self) -> None:
        """Notify all registered observers that the scan results are
        ready to be pulled and processed."""
        for observer in self.__observers:
            asyncio.create_task(observer.update())

    async def _scan_target_port(self, domain: str, port: int) -> None:
        """Perform a TCP handshake on a target socket."""
        with contextlib.suppress(ConnectionRefusedError,
                                 asyncio.TimeoutError,
                                 OSError):
            await asyncio.wait_for(asyncio.open_connection(
                domain, port, loop=self.__loop), timeout=self.timeout)
            self.results.append(f"{self.port_mapping[port]}://{domain}")

    @staticmethod
    async def _fetch_headers(session, url: str) -> dict[str, dict]:
        """
        Fetch the headers from a specific URL.

        Returns:
            A dictionary with the format {URL: {HEADERS}} upon a
                successful operation or {URL: {ERRORS}} otherwise.
        """

        try:
            async with session.get(url) as response:
                await response.text()
                return {url: dict(response.headers)}
        except aiohttp.ClientConnectorCertificateError as e:
            return {url: {
                "Error": f"{e.__class__.__name__}: An invalid TLS certificate "
                         f"was returned by the host"}}

    def _analyse_headers(self) -> None:
        """Perform an analysis in which each header fetched by the
        probe is sorted by frequency of appearance."""
        headers_by_keys = defaultdict(list)
        for result in self.headers:
            (url, headers), = result.items()
            for key, value in headers.items():
                headers_by_keys[key].extend([f"{url} > {key}: {value}"])
        self.analysed_headers = {
            key: headers_by_keys[key] for key in sorted(
                headers_by_keys,
                key=lambda k: len(headers_by_keys[k])
            )
        }

    def _get_port_from_proto(self, protocol: str) -> int:
        """Get a port number from a protocol name."""
        for port, proto in self.port_mapping.items():
            if proto.lower() == protocol.lower():
                return port

    def execute(self) -> list[str]:
        """
        Execute the asynchronous scan on each combination of target
        domains and port numbers.

        Returns:
            A list containing the URL of each live server that
                responded to the probes.
        """

        if self.prefer_https is True:
            '''When 'prefer_https' is True, requests to the HTTP port 
            (default 80, unless rebound) are initially skipped. If 
            responses with the HTTPS URI scheme are received for a 
            given domain, then this domain is excluded from the targets 
            list. Finally, on a second call to the scan tasks, the 
            targets remaining on the list are probed just on the HTTP 
            port.'''
            http_port: int = self._get_port_from_proto("http")
            self.ports.remove(http_port)
            self.__loop.run_until_complete(asyncio.wait(self._run_scan_tasks()))
            [self.targets.remove(url.split("//")[1]) for url in self.results]
            self.ports = http_port,

        if len(self.targets) > 0:
            self.__loop.run_until_complete(asyncio.wait(self._run_scan_tasks()))

        if self.fetch_headers is True:
            self.__loop.run_until_complete(self._run_fetch_headers())

        if self.analyse_headers is True:
            self._analyse_headers()

        self.__loop.run_until_complete(self._notify_all())
        return self.results


class WebProbeProxy(object):
    def __init__(self, *,
                 targets: Union[str, Path, Collection[str]],
                 ports: Union[int, str, Collection[int]] = None,
                 timeout: int = 5,
                 prefer_https: bool = False,
                 fetch_headers: bool = False,
                 analyse_headers: bool = False,
                 port_mapping: Union[str, Mapping] = None):
        """Proxy class for WebProbe.

        Allows greater flexibility when using WebProbe by parsing and
        converting inputs of different types before instantiating
        WebProbe and executing a scan.

        Args:
            targets: A string defining a single or comma-separated
                sequence targets, the absolute path to a file
                containing line-separated targets or a collection of
                targets as strings. Targets can be either IP addresses
                or domain names.
            ports: A single integer value with a valid port number as
                regulated by IETF RFC 6335, a string defining a single
                or comma-separated sequence of ports or a collection of
                port numbers as integers. Defaults to 80 and 443.
        """

        self.targets = targets
        self.port_mapping = port_mapping
        self.ports = ports
        self.timeout = timeout
        self.prefer_https = prefer_https
        self.analyse_headers = analyse_headers
        self.fetch_headers = True if analyse_headers is True else fetch_headers
        self.webprobe = WebProbe(targets=self.targets,
                                 ports=self.ports,
                                 timeout=self.timeout,
                                 prefer_https=self.prefer_https,
                                 port_mapping=self.port_mapping,
                                 fetch_headers=self.fetch_headers,
                                 analyse_headers=self.analyse_headers)

    def __setattr__(self, key, value):
        with contextlib.suppress(AttributeError):
            '''Allow the attributes of WebProbe to be silently updated 
            whenever those of WebProbeProxy are modified'''
            setattr(self.webprobe, key, value)
        super().__setattr__(key, value)

    def execute(self):
        return self.webprobe.execute()

    def register(self, observer):
        return self.webprobe.register(observer=observer)

    @property
    def port_mapping(self):
        """Gets port mapping.

        Sets a port mapping by parsing a string that maps port numbers
        to protocol names and transforms it into a dictionary.
        Ex: From '8080:http,9900:https' to {8080:'http',9900:'https'}
        """
        return self._port_mapping

    @port_mapping.setter
    def port_mapping(self, value: Union[str, Mapping, None]):
        if issubclass(value.__class__, Mapping):
            self._port_mapping = value
        elif value is None:
            self._port_mapping = {80: "http", 443: "https"}
        else:
            port_mapping = dict()
            for binding in value.split(","):
                for port, protocol in binding.split(":"):
                    port_mapping[int(port)] = protocol.strip()
            self._port_mapping = port_mapping

    @property
    def targets(self):
        """Gets targets.

        Sets the targets by converting each acceptable type into a list
        of strings appropriate for the instantiation of WebProbe.
        """
        return self._targets

    @targets.setter
    def targets(self, value: Union[str, Path, Collection[str]]):
        def __parse_file(filename: str) -> Iterator[str]:
            """Yield an iterator of strings extracted from the lines of
            a text file."""
            try:
                with open(file=filename, mode="r", encoding="utf_8") as file:
                    yield from (line.strip() for line in file)
            except PermissionError:
                raise SystemExit(f"Permission denied when reading the file "
                                 f"{filename}")

        if isinstance(value, str) or issubclass(value.__class__, Path):
            if Path(value).is_file():
                self._targets = list(__parse_file(filename=value))
            else:
                self._targets = [address.strip() for address in
                                 value.split(",")]
        elif issubclass(value.__class__, Collection):
            self._targets = list(value)
        else:
            raise SystemExit("Cannot proceed without specifying at least one "
                             "target IP address or domain name")

    @property
    def ports(self):
        """Gets port numbers.

        Sets the port numbers by converting each acceptable type into a
        list of integers appropriate for the instantiation of
        WebProbe.
        """
        return self._ports

    @ports.setter
    def ports(self, value: Union[int, str, Collection[int]]):
        if value is None:
            self._ports = list(self.port_mapping.keys())
        elif isinstance(value, int):
            self._ports = [value]
        elif isinstance(value, str):
            self._ports = [int(port) for port in value.split(",")]
        elif issubclass(value.__class__, Collection):
            self._ports = list(value)
        else:
            raise SystemExit(f"Invalid input type for port numbers: {value}")


if __name__ == "__main__":
    import argparse

    '''Unused import. Prevents raising a LookupError exception when 
    running the Pyinstaller-generated executable on dist/webprobe'''
    # noinspection PyUnresolvedReferences
    import encodings.idna

    from src.output import ResultsToFile, ResultsToScreen, HeadersToFile, \
        HeaderAnalysisToFile

    usage = ("Usage examples:\n"
             "\t1. python3 webprobe.py -t google.com\n"
             "\t2. python3 webprobe.py "
             "-t 45.33.32.156,demo.testfire.net,18.192.172.30 -p 443\n"
             "\t3. python3 webprobe.py --prefer-https -t uber.com,paypal.com\n"
             "\t4. python3 webprobe.py -t unusual-domain.xyz "
             "--rebind 1337:https\n"
             "\t5. python3 webprobe.py -t /path/to/domains/file.txt\n")

    parser = argparse.ArgumentParser(
        description="WebProbe: Asynchronous TCP port scanner for live web "
                    "hosts",
        epilog=usage,
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("-t", "--targets", type=str, metavar="ADDRESSES",
                        required=True,
                        help="An absolute path to a valid file with "
                             "line-separated targets, a single target name or "
                             "a comma-separated sequence of targets to probe, "
                             "e.g., '45.33.32.156,65.61.137.117,"
                             "testphp.vulnweb.com'")
    parser.add_argument("-p", "--ports", type=str, default=None,
                        help="A comma-separated sequence of port numbers "
                             "and/or port ranges to scan on each target "
                             "specified, e.g., '20-25,53,80,443'.")
    parser.add_argument("--timeout", type=int, default=5, metavar="TIME",
                        help="Time to wait for a response from a target before "
                             "closing a connection (defaults to 5 seconds).")
    parser.add_argument("--prefer-https", action="store_true",
                        help="Omit performing requests with the HTTP URI "
                             "scheme for those servers that also respond with "
                             "HTTPS (defaults to False).")
    parser.add_argument("--rebind", type=str, default=None, metavar="MAP",
                        help="Allows ports other than 80 and 443 to be "
                             "assigned to HTTP and HTTPS, respectively. Takes "
                             "input with the syntax '8080:http' or "
                             "'8080:http,9900:https'. Defaults to standard "
                             "port bindings 80:HTTP and 443:HTTPS.")
    parser.add_argument("--silent", action="store_true",
                        help="Suppress displaying results to STDOUT.")
    parser.add_argument("-o", "--output", type=str, default=None,
                        metavar="PATH",
                        help="Absolute path to a file in which to write "
                             "results of probing each web host.")
    parser.add_argument("--headers", type=str, default=None, metavar="PATH",
                        help="Absolute path to a directory in which to write "
                             "files with the response headers for each probed "
                             "URL.")
    parser.add_argument("--header-analysis", type=str, default=None,
                        metavar="PATH",
                        help="Absolute path to a file in which to write all "
                             "fetched headers in ascending order of frequency.")

    cli_args = parser.parse_args()

    probe = WebProbeProxy(targets=cli_args.targets,
                          ports=cli_args.ports,
                          timeout=cli_args.timeout,
                          prefer_https=cli_args.prefer_https,
                          port_mapping=cli_args.rebind,
                          fetch_headers=bool(cli_args.headers),
                          analyse_headers=bool(cli_args.header_analysis))

    if cli_args.silent is False:
        ResultsToScreen(subject=probe)
    if cli_args.output is not None:
        ResultsToFile(subject=probe, file_path=cli_args.output)
    if cli_args.headers is not None:
        HeadersToFile(subject=probe, directory_path=cli_args.headers)
    if cli_args.header_analysis is not None:
        HeaderAnalysisToFile(subject=probe, file_path=cli_args.header_analysis)

    probe.execute()
