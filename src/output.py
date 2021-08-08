import abc
import asyncio
from pathlib import Path
from typing import Union

from src.webprobe import WebProbe, WebProbeProxy
from src.webprobe_exceptions import WebProbeInvalidPath, WebProbeAccessDenied


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
    """Print all results to STDOUT."""

    def __init__(self, *, subject: Union[WebProbe, WebProbeProxy]):
        super().__init__(subject)
        self.scan = subject

    async def update(self) -> None:
        print(*self.scan.webprobe.results, sep="\n")
        await asyncio.sleep(0)


class ResultsToFile(OutputMethod):
    """Write all results to a file."""

    def __init__(self, *,
                 subject: Union[WebProbe, WebProbeProxy],
                 file_path: Union[str, Path]):
        super().__init__(subject)
        self.scan = subject
        self.path = file_path

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        try:
            self._path = Path(value)
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except TypeError:
            raise WebProbeInvalidPath(
                f"Invalid file name or type: {self._path}")
        except PermissionError:
            raise WebProbeAccessDenied(
                f"Permission denied when writing to file {self._path}")

    async def update(self) -> None:
        with open(file=self.path, mode="w", encoding="utf_8") as file:
            [file.write(f"{result}\n") for result in self.scan.webprobe.results]
        await asyncio.sleep(0)


class HeadersToFile(OutputMethod):
    """Write the headers returned by a request to each live web host to
    a separate file named after the domain."""

    def __init__(self, *,
                 subject: Union[WebProbe, WebProbeProxy],
                 directory_path: Union[str, Path]):
        super().__init__(subject)
        self.scan = subject
        self.dir_path = directory_path

    @property
    def dir_path(self):
        return self._dir_path

    @dir_path.setter
    def dir_path(self, value):
        try:
            self._dir_path = Path(value)
            self._dir_path.mkdir(parents=True, exist_ok=True)
        except TypeError:
            raise WebProbeInvalidPath(
                f"Invalid name for directory: {self._dir_path}")
        except PermissionError:
            raise WebProbeAccessDenied(
                f"Permission denied when creating directory {self._dir_path}")

    async def update(self) -> None:
        for result in self.scan.webprobe.headers:
            (url, headers), = result.items()
            domain: str = url.split("//")[1]
            file_path: Path = self.dir_path.joinpath(f"{domain}.head")
            with open(file=file_path, mode="a", encoding="utf_8") as file:
                file.write(f"{url}\n")
                for key, value in headers.items():
                    file.write(f"\t{key}: {value}\n")
                file.write("\n")
        await asyncio.sleep(0)


class HeaderAnalysisToFile(OutputMethod):
    """Write a file containing a frequency analysis for each header
    fetched by the probe."""

    def __init__(self, *,
                 subject: Union[WebProbe, WebProbeProxy],
                 file_path: Union[str, Path]):
        super().__init__(subject)
        self.scan = subject
        self.path = file_path

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        try:
            self._path = Path(value)
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except TypeError:
            raise WebProbeInvalidPath(
                f"Invalid file name or type: {self._path}")
        except PermissionError:
            raise WebProbeAccessDenied(
                f"Permission denied when writing to file {self._path}")

    async def update(self) -> None:
        with open(file=self.path, mode="w", encoding="utf_8") as file:
            for key, value in self.scan.webprobe.analysed_headers.items():
                file.write(f"[{key}]")
                [file.write(f"\n\t{data}") for data in value]
                file.write(f"\n\n")
        await asyncio.sleep(0)
