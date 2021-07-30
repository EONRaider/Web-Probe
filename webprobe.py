#!/usr/bin/env python3
# https://github.com/EONRaider/Web-Probe

__author__ = 'EONRaider @ keybase.io/eonraider'

import abc
import asyncio
import contextlib
from pathlib import Path
from typing import Iterable, Iterator, Union


class WebProbe(object):
    def __init__(self,
                 targets: Union[str, Path, Iterable[str]],
                 ports: Union[int, Iterable[int]] = None,
                 timeout: int = 5,
                 prefer_https: bool = False,
                 rebind_ports: str = None):
        """Perform asynchronous TCP-connect scans on combinations of
        target hosts and port numbers.

        Args:
            targets (Iterable[str]): An iterable of strings defining a
                sequence of IP addresses and/or domain names.
            ports (Iterable[int]): An iterable of integers defining a
                sequence of valid port numbers as regulated by IETF
                RFC 6335.
            timeout (int): Time to wait for a response from a target
                before closing a connection to it. Setting this to too
                short an interval may prevent the scanner from waiting
                the time necessary to receive a valid response from a
                live server, generating a false-negative by identifying
                a result as a timeout too soon. Recommended setting to
                a minimum of 5 seconds.
            prefer_https (bool): Omit performing requests with the HTTP
                URI scheme for those servers that also respond with
                HTTPS.
            rebind_ports (str): Allows ports other than 80 and 443 to
                be assigned to HTTP and HTTPS, respectively. Takes
                input with the syntax '8080:http' or
                '8080:http,9900:https'
        """

        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.prefer_https = prefer_https
        self.port_mapping = dict()
        self.rebind_ports = rebind_ports
        self.results = list()
        self.__loop = asyncio.get_event_loop()
        self.__observers = list()

    @property
    def rebind_ports(self):
        return self._rebind_ports

    @rebind_ports.setter
    def rebind_ports(self, value):
        if value is None:
            self.port_mapping = {80: "http", 443: "https"}
        else:
            for setting in value.split(","):
                for mapping in setting:
                    port, scheme = mapping.split(":")
                    self.port_mapping[int(port)] = scheme.strip()
        self._rebind_ports = value

    @property
    def targets(self):
        return self._targets

    @targets.setter
    def targets(self, value: Union[str, Path, Iterable[str]]):
        def _parse_file(filename: str) -> Iterator[str]:
            """Yield an iterator of strings extracted from the lines of
            a text file"""
            try:
                with open(file=filename, mode="r", encoding="utf_8") as file:
                    yield from (line.strip() for line in file)
            except FileNotFoundError:
                raise SystemExit(f'File {filename} not found.')
            except PermissionError:
                raise SystemExit(f'Permission denied when reading the file '
                                 f'{filename}')

        if value is None:
            raise SystemExit("Cannot proceed without specifying at least one "
                             "target address")
        elif isinstance(value, str):
            if Path(value).is_file():
                self._targets = list(_parse_file(filename=value))
            else:
                self._targets = [address.strip() for address in
                                 value.split(",")]
        elif issubclass(value.__class__, Iterable):
            self._targets = list(value)

    @property
    def ports(self):
        return self._ports

    @ports.setter
    def ports(self, value: Union[int, str, Iterable[int]]):
        if value is None:
            self._ports = [80, 443]
        elif isinstance(value, int):
            self._ports = [value]
        elif isinstance(value, str):
            self._ports = [int(port.strip()) for port in value.split(",")]
        elif issubclass(value.__class__, Iterable):
            self._ports = list(value)
        else:
            raise SystemExit(f"Invalid input type for port numbers: {value}")

    def _set_scan_tasks(self):
        """Set up a scan coroutine for each combination of target
        domain and port number."""
        return [self._scan_target_port(target, port) for port in self.ports
                for target in self.targets]

    def register(self, observer):
        """Register a class that implements the interface of
        OutputMethod as an observer."""
        self.__observers.append(observer)

    async def _notify_all(self):
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

    def execute(self) -> list:
        """
        Execute the asynchronous scan on each combination of target
        domains and port numbers.

        Returns:
            A list containing the URL of each live server that
                responded to the probes.
        """

        if self.prefer_https is True:
            '''When 'prefer_https' is True, requests to port 80 are 
            initially skipped. If responses with the HTTPS URI scheme 
            are received for a given domain, then this domain is 
            excluded from the targets list. Finally, on a second call 
            to the scan tasks, the remaining targets on the list are 
            probed on port 80.'''
            self.ports = 443,
            self.__loop.run_until_complete(asyncio.wait(self._set_scan_tasks()))
            for result in self.results:
                self.targets.remove(result.split("//")[1])
            self.ports = 80,
        self.__loop.run_until_complete(asyncio.wait(self._set_scan_tasks()))
        self.__loop.run_until_complete(self._notify_all())
        return self.results


class OutputMethod(abc.ABC):
    """
    Interface for the implementation of all classes responsible for
    further processing and/or output of the information gathered by
    the WebProbe class.
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
        print(*(result for result in self.scan.results), sep="\n")
        await asyncio.sleep(0)


if __name__ == '__main__':
    import argparse

    usage = ('Usage examples:\n'
             '1. python3 simple_async_scan.py google.com -p 80,443\n'
             '2. python3 simple_async_scan.py '
             '45.33.32.156,demo.testfire.net,18.192.172.30 '
             '-p 20-25,53,80,111,135,139,443,3306,5900')

    parser = argparse.ArgumentParser(
        description='Simple asynchronous TCP Connect port scanner',
        epilog=usage,
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('targets', type=str, metavar='ADDRESSES',
                        help="A comma-separated sequence of IP addresses "
                             "and/or domain names to scan, e.g., "
                             "'45.33.32.156,65.61.137.117,"
                             "testphp.vulnweb.com'.")
    parser.add_argument('-p', '--ports', type=str, required=True,
                        help="A comma-separated sequence of port numbers "
                             "and/or port ranges to scan on each target "
                             "specified, e.g., '20-25,53,80,443'.")
    parser.add_argument('--timeout', type=float, default=10.0,
                        help='Time to wait for a response from a target before '
                             'closing a connection (defaults to 10.0 seconds).')
    parser.add_argument('--open', action='store_true',
                        help='Only show open ports in scan results.')
    cli_args = parser.parse_args()

    scanner = WebProbe.from_csv_strings(targets=cli_args.targets,
                                        ports=cli_args.ports,
                                        timeout=cli_args.timeout)

    ResultsToScreen(subject=scanner)
    scanner.execute()
