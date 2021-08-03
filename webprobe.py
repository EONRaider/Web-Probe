#!/usr/bin/env python3
# https://github.com/EONRaider/Web-Probe

__author__ = 'EONRaider @ keybase.io/eonraider'

import abc
import asyncio
import contextlib
from pathlib import Path
from typing import Collection, Coroutine, Iterator, Mapping, Union


class WebProbe(object):
    def __init__(self, *,
                 targets: list[str],
                 ports: list[int],
                 timeout: Union[int, float],
                 prefer_https: bool,
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
            port_mapping (Mapping): Allows ports other than 80 and 443
                to be assigned to HTTP and HTTPS, respectively. Ex:
                Dictionaries with the syntax {8080:'http'} or
                {8080:'http',9900:'https'}
        """

        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.prefer_https = prefer_https
        self.port_mapping = port_mapping
        self.results = list()
        self.__loop = asyncio.get_event_loop()
        self.__observers = list()

    def _set_scan_tasks(self) -> list[Coroutine]:
        """Set up a scan coroutine for each combination of target
        domain and port number."""
        return [self._scan_target_port(target, port) for port in self.ports
                for target in self.targets]

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
        """Perform a TCP handshake on a pair of target domain and
        port number."""
        with contextlib.suppress(ConnectionRefusedError,
                                 asyncio.TimeoutError,
                                 OSError):
            await asyncio.wait_for(asyncio.open_connection(
                domain, port, loop=self.__loop), timeout=self.timeout)
            self.results.append(f"{self.port_mapping[port]}://{domain}")

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
            self.__loop.run_until_complete(asyncio.wait(self._set_scan_tasks()))
            [self.targets.remove(url.split("//")[1]) for url in self.results]
            self.ports = http_port,
        self.__loop.run_until_complete(asyncio.wait(self._set_scan_tasks()))
        self.__loop.run_until_complete(self._notify_all())
        return self.results


class WebProbeProxy(object):
    def __init__(self, *,
                 targets: Union[str, Path, Collection[str]],
                 ports: Union[int, str, Collection[int]] = None,
                 timeout: int = 5,
                 prefer_https: bool = False,
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
        self.webprobe = WebProbe(targets=self.targets,
                                 ports=self.ports,
                                 timeout=self.timeout,
                                 prefer_https=self.prefer_https,
                                 port_mapping=self.port_mapping)

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
        return self._targets

    @targets.setter
    def targets(self, value: Union[str, Path, Collection[str]]):
        def __parse_file(filename: str) -> Iterator[str]:
            """Yield an iterator of strings extracted from the lines of
            a text file"""
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


class OutputMethod(abc.ABC):
    """
    Interface for the implementation of all classes responsible for
    further processing and/or output of the information gathered by
    the WebProbe class and its inheritors.
    """

    def __init__(self, subject):
        subject.register(self)

    @abc.abstractmethod
    async def update(self, *args, **kwargs):
        pass


class ResultsToScreen(OutputMethod):
    def __init__(self, subject):
        super().__init__(subject)
        self.scan = subject

    async def update(self):
        print(*(result for result in self.scan.webprobe.results), sep="\n")
        await asyncio.sleep(0)


if __name__ == "__main__":
    import argparse

    usage = ("Usage examples:\n"
             "1. python3 webprobe.py -t google.com\n"
             "2. python3 webprobe.py "
             "-t 45.33.32.156,demo.testfire.net,18.192.172.30 -p 443\n"
             "3. python3 webprobe.py --prefer-https -t uber.com,paypal.com\n"
             "4. python3 webprobe.py -t unusual-domain.xyz "
             "--rebind 1337:https\n"
             "5. python3 webprobe.py -t /path/to/domains/file.txt")

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
    parser.add_argument("--prefer-https", type=bool, default=False,
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

    cli_args = parser.parse_args()

    scanner = WebProbeProxy(targets=cli_args.targets,
                            ports=cli_args.ports,
                            timeout=cli_args.timeout,
                            prefer_https=cli_args.prefer_https,
                            port_mapping=cli_args.rebind)

    if cli_args.silent is False:
        ResultsToScreen(subject=scanner)

    scanner.execute()
