#!/usr/bin/env python3
# https://github.com/EONRaider/Web-Probe

__author__ = 'EONRaider @ keybase.io/eonraider'


class WebProbeException(Exception):
    def __init__(self, message: str = None, *, code: int = None):
        super().__init__(message, code)
        self.message = message
        self.code = code


class WebProbeInvalidPath(WebProbeException):
    ...


class WebProbeAccessDenied(WebProbeException):
    ...


class WebProbeInvalidInput(WebProbeException):
    ...
