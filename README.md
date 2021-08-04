# Web Probe

![Python Version](https://img.shields.io/badge/python-3.7+-blue?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/GNU%2FLinux-red?style=for-the-badge&logo=linux)
![OS](https://img.shields.io/badge/OSX-gray?style=for-the-badge&logo=apple)
![OS](https://img.shields.io/badge/Windows-blue?style=for-the-badge&logo=windows)
[![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/EONRaider/web-probe?style=for-the-badge)](https://www.codefactor.io/repository/github/EONRaider/web-probe)
[![License](https://img.shields.io/github/license/EONRaider/Packet-Sniffer?style=for-the-badge)](https://github.com/EONRaider/Packet-Sniffer/blob/master/LICENSE)

[![Reddit](https://img.shields.io/badge/Reddit-EONRaider-FF4500?style=flat-square&logo=reddit)](https://www.reddit.com/user/eonraider)
[![Discord](https://img.shields.io/badge/Discord-EONRaider-7289DA?style=flat-square&logo=discord)](https://discord.gg/KVjWBptv)
[![Twitter](https://img.shields.io/badge/Twitter-eon__raider-38A1F3?style=flat-square&logo=twitter)](https://twitter.com/intent/follow?screen_name=eon_raider)

Web Probe is a Python 3 asynchronous port scanner with the purpose of 
checking live web servers. It uses Python's Standard Library `asyncio` 
framework to create TCP connections to an arbitrary number of ports on target IP 
addresses and/or domain names. It can probe an unlimited number of hosts
simultaneously, **effectively scanning thousands of hosts within just a few
seconds.**

Furthermore, WebProbe fetches response headers from each target and parses
them all, writing a file that displays a frequency analysis of headers. This
is useful for finding *unusual headers* that may indicate the presence of a
given system or vulnerability within a large set of targets.

This application can be run by any Python v3.7+ interpreter or as a 
**stand-alone executable** on 64-bit GNU/Linux, Apple MacOS or Microsoft Windows.

## Installation

WebProbe can be run as a multi-platform executable thanks to 
[PyInstaller](https://github.com/pyinstaller/pyinstaller).

Simply download the `web_probe` file with from the `dist` directory 
[at this location](https://github.com/EONRaider/Web-Probe/blob/master/dist/webprobe),
grant it permissions to execute in the local context and run it as 
described in the following [Usage](#usage) section.
```shell
# In the directory where the webprobe executable is located
user@host:~$ chmod 740 webprobe
user@host:~$ webprobe --help
```

### Use it as a custom command
On GNU/Linux or MacOS, either download the `webprobe` executable or create a symbolic
link to it in a directory listed in the `$PATH` environment variable to 
have `WebProbe` set up as a command in your system.

## Usage
```
usage: webprobe [-h] -t ADDRESSES [-p PORTS] [--timeout TIME] [--prefer-https] [--rebind MAP] [--silent] [-o PATH] [--headers PATH] [--header-analysis PATH]

WebProbe: Asynchronous TCP port scanner for live web hosts

optional arguments:
  -h, --help            show this help message and exit
  -t ADDRESSES, --targets ADDRESSES
                        An absolute path to a valid file with line-separated targets, a single target name or a comma-separated sequence of targets to probe, e.g., '45.33.32.156,65.61.137.117,testphp.vulnweb.com'
  -p PORTS, --ports PORTS
                        A comma-separated sequence of port numbers and/or port ranges to scan on each target specified, e.g., '20-25,53,80,443'.
  --timeout TIME        Time to wait for a response from a target before closing a connection (defaults to 5 seconds).
  --prefer-https        Omit performing requests with the HTTP URI scheme for those servers that also respond with HTTPS (defaults to False).
  --rebind MAP          Allows ports other than 80 and 443 to be assigned to HTTP and HTTPS, respectively. Takes input with the syntax '8080:http' or '8080:http,9900:https'. Defaults to standard port bindings 80:HTTP and 443:HTTPS.
  --silent              Suppress displaying results to STDOUT.
  -o PATH, --output PATH
                        Absolute path to a file in which to write results of probing each web host.
  --headers PATH        Absolute path to a directory in which to write files with the response headers for each probed URL.
  --header-analysis PATH
                        Absolute path to a file in which to write all fetched headers in ascending order of frequency.

Usage examples:
	1. python3 webprobe.py -t google.com
	2. python3 webprobe.py -t 45.33.32.156,demo.testfire.net,18.192.172.30 -p 443
	3. python3 webprobe.py --prefer-https -t uber.com,paypal.com
	4. python3 webprobe.py -t unusual-domain.xyz --rebind 1337:https
	5. python3 webprobe.py -t /path/to/domains/file.txt

```
## Usage Examples

#### View the help prompt
```shell
user@host:~$ webprobe --help
usage: webprobe [-h] -t ADDRESSES [-p PORTS] [--timeout TIME] [--prefer-https] [--rebind MAP] [--silent] [-o PATH] [--headers PATH] [--header-analysis PATH]

WebProbe: Asynchronous TCP port scanner for live web hosts
(...snip...)
```

#### Probe a single domain
```shell
user@host:~$ webprobe --target google.com
https://google.com
http://google.com
```

#### Probe multiple domains on a single port number
```shell
user@host:~$ webprobe -t facebook.com,scanme.nmap.org,instagram.com -p 443
https://facebook.com
https://instagram.com
```

#### Probe multiple domains from a text file
```shell
user@host:~$ cat domains.txt
google.com
uber.com
paypal.com
user@host:~$ webprobe -t domains.txt
http://google.com
https://google.com
http://uber.com
https://uber.com
https://paypal.com
http://paypal.com
```

## Legal Disclaimer

The use of code contained in this repository, either in part or in its totality,
for engaging targets without prior mutual consent is illegal. **It is
the end user's responsibility to obey all applicable local, state and 
federal laws.**

Developers assume **no liability** and are not
responsible for misuses or damages caused by any code contained
in this repository in any event that, accidentally or otherwise, it comes to
be utilized by a threat agent or unauthorized entity as a means to compromise
the security, privacy, confidentiality, integrity, and/or availability of
systems and their associated resources by leveraging the exploitation of known
or unknown vulnerabilities present in said systems, including, but not limited
to, the implementation of security controls, human- or electronically-enabled.

The use of this code is **only** endorsed by the developers in those
circumstances directly related to **educational environments** or
**authorized penetration testing engagements** whose declared purpose is that
of finding and mitigating vulnerabilities in systems, limiting their exposure
to compromises and exploits employed by malicious agents as defined in their
respective threat models.
