# PacketQ

[![Total alerts](https://img.shields.io/lgtm/alerts/g/DNS-OARC/PacketQ.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/DNS-OARC/PacketQ/alerts/) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=dns-oarc%3APacketQ&metric=bugs)](https://sonarcloud.io/dashboard?id=dns-oarc%3APacketQ) [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=dns-oarc%3APacketQ&metric=security_rating)](https://sonarcloud.io/dashboard?id=dns-oarc%3APacketQ)

`packetq` is a command line tool to run SQL queries directly on PCAP files,
the results can be outputted as JSON (default), formatted/compact CSV and XML.
It also contain a very simplistic web-server in order to inspect PCAP files
remotely. PacketQ was previously known as DNS2db but was renamed in 2011 when
it was rebuilt and could handle protocols other than DNS among other things.

More information is provided in our [FAQ](FAQ.md), [functions](FUNCTIONS.md),
and [fields](FIELDS.md) documentation.

A short demo-video of PacketQ's capabilities is available on http://www.youtube.com/watch?v=70wJmWZE9tY

## Features

* Super-fast native decoding of PCAP-files (even gzipped) and dirt-quick in-memory sorting algorithms.
* A extensible protocol decoding design with build in support for ICMP and DNS from start.
* Support for grouping, sorting, counting and most other important SQL-functions.
* Only dependent on zlib, no other hard-to-find libs needed. Compiles on everything.
* Build-in web-server, JSON API and a simple JQuery-based GUI concept application with graphs.
* Can be designed to cache queries by pre-processing PCAPs into static JSON-files that can be used to make queries again.
* Built in DNS-resolver function (used by GUI).
* Support for sampling. Helps when making queries to large, uniform PCAP-files.
* Can convert flags in packet-headers to text on the fly.
* Can make multiple queries towards the same data in memory.

More information may be found here:
- https://www.dns-oarc.net/tools/packetq

Issues should be reported here:
- https://github.com/DNS-OARC/PacketQ/issues

General support and discussion:
- Mattermost: https://chat.dns-oarc.net/community/channels/oarc-software

## Dependencies

PacketQ requires a couple of libraries beside a normal C++ compiling
environment with Autoconf and Automake.

To install the dependencies under Debian/Ubuntu:
```
apt-get install -y zlib1g-dev
```

To install the dependencies under CentOS (with EPEL enabled):
```
yum install -y zlib-devel
```

## Build from GitHub

```
git clone https://github.com/DNS-OARC/PacketQ.git
cd PacketQ
./autogen.sh
./configure [options]
make
make install
```

## Building from source tarball

The [source tarball from DNS-OARC](https://www.dns-oarc.net/tools/packetq)
comes prepared with `configure`:

```
tar zxvf packetq-version.tar.gz
cd packetq-version
./configure [options]
make
make install
```

## Usage example

Retrieves the 10 first packets containing DNS information from the file
`sample.pcap`:

```
packetq -s "select * from dns limit 10" sample.pcap
```

Starts a web-server on port 8080 (`-p8080`) as a daemon (`-d`) serving files
from the directory `html/` (`-w html/`) and PCAP files from the directory
`pcap/` (`-r pcap/`):

```
packetq -d -p8080 -w html/ -r pcap/
```

## Author(s)

- Per Granå [@Per-Grana](https://github.com/Per-Grana)

## Contributor(s)

- Ole Laursen [@OleLaursen](https://github.com/OleLaursen)
- Rickard Dahlstrand [@rickarddahlstrand](https://github.com/rickarddahlstrand)
- Jerry Lundström [@jelu](https://github.com/jelu)
- Magnus Lundén [@ripoff](https://github.com/ripoff)
- Roger Murray [@romu42](https://github.com/romu42)
- Henrik Levkowetz [@levkowetz](https://github.com/levkowetz)

See also the [full list of contributors](https://github.com/DNS-OARC/PacketQ/graphs/contributors).

## Copyright

Copyright (c) 2017-2020, OARC, Inc.

Copyright (c) 2011-2017, IIS - The Internet Foundation in Sweden

All rights reserved.

```
This file is part of PacketQ.

PacketQ is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

PacketQ is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with PacketQ.  If not, see <http://www.gnu.org/licenses/>.
```
