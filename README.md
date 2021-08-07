# Web Probe

![Python Version](https://img.shields.io/badge/python-3.7+-blue?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/GNU%2FLinux-red?style=for-the-badge&logo=linux)
![OS](https://img.shields.io/badge/mac%20OS-gray?style=for-the-badge&logo=apple)
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

Furthermore, WebProbe optionally fetches response headers from each target
and parses them all, writing a file that displays a frequency analysis for 
those headers. This is useful for finding *unusual headers* that may 
indicate the presence of a given system, infrastructure signature or 
vulnerability within a large set of targets.

This application can be run by any Python v3.7+ interpreter, by a system 
running **Docker** or, alternatively, as a **standalone executable** on 
64-bit GNU/Linux, Apple macOS or Microsoft Windows. In fact, you don't 
even need Python installed on your local environment to run WebProbe.

## Installation

### From a standalone, multi-platform executable
WebProbe can be run as a **multi-platform** executable thanks to 
[PyInstaller](https://github.com/pyinstaller/pyinstaller).

Simply [click here](https://github.com/EONRaider/Web-Probe/raw/master/dist/webprobe)
to download the `webprobe` file from the 
[dist directory](https://github.com/EONRaider/Web-Probe/blob/master/dist/webprobe).
Then just grant it permissions to execute in the local context and run it as 
described in the following [Usage](#usage) section.

- **Use it as a command**: On GNU/Linux or MacOS, either 
download the `webprobe` executable or create a symbolic
link to it in a convenient directory listed in the `$PATH` environment 
variable to have `WebProbe` set up as a command in your local system. Take
a look [here](https://stackoverflow.com/a/29235240) if you need help setting
this up.

### From a Docker image
Pull the image from DockerHub and check the help prompt with a single
command:
```
user@host:~$ docker run -it eonraider/webprobe --help
```

### From a Virtual Environment
Better suited for development and eventual contributions to the project:
```
user@host:~$ git clone https://github.com/EONRaider/Web-Probe
user@host:~$ cd Web-Probe
user@host:~/Web-Probe$ python3 -m venv venv
(venv) user@host:~/Web-Probe$ source venv/bin/activate
(venv) user@host:~/Web-Probe$ pip install -r dev-requirements.txt
```

## Usage
```
usage: webprobe.py [-h] -t ADDRESSES [-p PORTS] [--timeout SECONDS]
                   [--prefer-https] [--rebind MAP] [--silent] [-o FILE_PATH]
                   [--headers DIR_PATH] [--header-analysis FILE_PATH]

WebProbe: Asynchronous TCP port scanner for live web hosts

optional arguments:
  -h, --help            show this help message and exit
  -t ADDRESSES, --targets ADDRESSES
                        An absolute path to a valid file with line-separated targets, a single target name or a comma-separated sequence of targets to probe, e.g., '45.33.32.156,65.61.137.117,testphp.vulnweb.com'
  -p PORTS, --ports PORTS
                        A comma-separated sequence of port numbers and/or port ranges to scan on each target specified, e.g., '20-25,53,80,443'.
  --timeout SECONDS     Time to wait for a response from a target before closing a connection (defaults to 5 seconds).
  --prefer-https        Omit performing requests with the HTTP URI scheme for those servers that also respond with HTTPS (defaults to False).
  --rebind MAP          Allows ports other than 80 and 443 to be assigned to HTTP and HTTPS, respectively. Takes input with the syntax '8080:http' or '8080:http,9900:https'. Defaults to standard port bindings 80:HTTP and 443:HTTPS.
  --silent              Suppress displaying results to STDOUT.
  -o FILE_PATH, --output FILE_PATH
                        Absolute path to a file in which to write results of probing each web host.
  --headers DIR_PATH    Absolute path to a directory in which to write files with the response headers for each probed URL.
  --header-analysis FILE_PATH
                        Absolute path to a file in which to write all fetched headers in ascending order of frequency.

Usage examples:
	1. python3 webprobe.py -t google.com
	2. python3 webprobe.py -t 45.33.32.156,demo.testfire.net,18.192.172.30 -p 443
	3. python3 webprobe.py --prefer-https -t uber.com,paypal.com
	4. python3 webprobe.py -t unusual-domain.xyz --rebind 1337:https
	5. python3 webprobe.py -t /path/to/domains/file.txt
```

## Why analyse response headers?

A good answer to this question can be found in
[this livestream](https://youtu.be/SYExiynPEKM?t=940) from
[Nahamsec](https://www.youtube.com/channel/UCCZDt7MuC3Hzs6IH4xODLBw)
YouTube channel, but basically an analysis of response headers allows you
to find unusual response patterns when performing recon on a target
(especially in a bug bounty hunting environment). Take a look at the
[sample header analysis](https://github.com/EONRaider/Web-Probe/blob/master/tests/support_files/webprobe-uber.com.head.analysis.txt)
for the uber.com domain included in this project's support files.


## Usage Examples

<details>
<summary>View the help prompt</summary>

```
user@host:~$ webprobe --help
usage: webprobe.py [-h] -t ADDRESSES [-p PORTS] [--timeout SECONDS]
                   [--prefer-https] [--rebind MAP] [--silent] [-o FILE_PATH]
                   [--headers DIR_PATH] [--header-analysis FILE_PATH]
                   
WebProbe: Asynchronous TCP port scanner for live web hosts
(...snip...)
```
</details>

<details>
<summary>Probe a single domain</summary>

```
user@host:~$ webprobe --targets google.com
https://google.com
http://google.com
```
</details>

<details>
<summary>Probe multiple domains on a single port number from the CLI</summary>

```
user@host:~$ webprobe -t facebook.com,scanme.nmap.org,instagram.com -p 443
https://facebook.com
https://instagram.com
```
</details>

<details>
<summary>Probe multiple domains from a text file</summary>

```
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
</details>

<details>
<summary>Probe a domain and fetch the response headers</summary>

```
user@host:~$ webprobe --targets google.com --headers .
http://google.com
https://google.com

user@host:~$ cat google.com.head
http://google.com
    Date: Wed, 04 Aug 2021 20:22:07 GMT
    Expires: -1
    Cache-Control: private, max-age=0
    Content-Type: text/html; charset=ISO-8859-1
    P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
    Content-Encoding: gzip
    Server: gws
    Content-Length: 6144
    X-XSS-Protection: 0
    X-Frame-Options: SAMEORIGIN
    Set-Cookie: 1P_JAR=2021-08-04-20; expires=Fri, 03-Sep-2021 20:22:07 GMT; path=/; domain=.google.com; Secure

https://google.com
    Date: Wed, 04 Aug 2021 20:22:07 GMT
    Expires: -1
    Cache-Control: private, max-age=0
    Content-Type: text/html; charset=ISO-8859-1
    P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
    Content-Encoding: gzip
    Server: gws
    X-XSS-Protection: 0
    X-Frame-Options: SAMEORIGIN
    Set-Cookie: 1P_JAR=2021-08-04-20; expires=Fri, 03-Sep-2021 20:22:07 GMT; path=/; domain=.google.com; Secure
    Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-T051=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"
    Transfer-Encoding: chunked
```
</details>


<details>
<summary>Probe 500+ domains from a text file and analyse their
response headers in just 8.5 seconds</summary>

```
# Using the tests file from this repository
user@host:~$ wc -l tests/support_files/amass-uber.com.txt
557 tests/support_files/amass-uber.com.txt <-- Number of domains to probe 

user@host:~$ time dist/webprobe --targets tests/support_files/amass-uber.com.txt \
--header-analysis ~/Desktop/header-analysis.txt

https://get.uber.com
https://wallet.uber.com
https://beta.uber.com
(...snip...)
https://safetycenter-staging.uber.com
https://dba.usuppliers.uber.com
http://sao2.uber.com

real	0m8,558s <-- Total time elapsed
user	0m2,809s
sys	0m0,345s

user@host:~$ cat ~/Desktop/header-analysis.txt
[CF-Ray]
	-> http://investor.uber.com > CF-Ray: 67aa80f63f6df758-GRU

[CF-Cache-Status]
	-> http://investor.uber.com > CF-Cache-Status: REVALIDATED

[Expect-CT]
	-> http://investor.uber.com > Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
(...snip...)
```
</details>

<details>
<summary>Use WebProbe from Docker image</summary>

Running a command for WebProbe using docker is as simple as using 
`docker run -it eonraider/webprobe` followed by the standard arguments 
described in the help prompt. The best way to extract output files 
relies on creating a volume binding a local system directory to a 
user-writable directory inside the container, such as `/tmp`.
```
# Simple probe from the CLI with results to STDOUT
user@host:~$ docker run -it eonraider/webprobe --targets paypal.com
http://paypal.com
https://paypal.com

# Using a volume to extract an output file from the Docker container
user@host:~$ docker run -v ~/Desktop:/tmp -it eonraider/webprobe \
--targets paypal.com -o /tmp/webprobe-paypal.com.txt
http://paypal.com
https://paypal.com

user@host:~$ cat ~/Desktop/webprobe-paypal.com.txt
http://paypal.com
https://paypal.com
```
</details>

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
