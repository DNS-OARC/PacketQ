Name:           packetq
Version:        1.4.1
Release:        1%{?dist}
Summary:        A tool that provides a basic SQL-frontend to PCAP-files
Group:          Productivity/Networking/DNS/Utilities

License:        GPL-3.0
URL:            https://github.com/DNS-OARC/PacketQ
Source0:        %{name}_%{version}.orig.tar.gz

BuildRequires:  zlib-devel
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  gcc-c++

%description
packetq is a command line tool to run SQL queries directly on PCAP files,
the results can be outputted as JSON (default), formatted/compact CSV and XML.
It also contain a very simplistic web-server in order to inspect PCAP files
remotely. PacketQ was previously known as DNS2db but was renamed in 2011 when
it was rebuilt and could handle protocols other than DNS among other things.


%prep
%setup -q -n %{name}_%{version}


%build
sh autogen.sh
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%check
make test


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root)
%{_bindir}/*
%{_datadir}/doc/*


%changelog
* Thu Nov 09 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.4.1-1
- Release 1.4.1
  * Fixed an issue with the in-memory representation of DNS records which
    was not initialized correctly and could cause the reuse of old data,
    especially if the record was incomplete (such as FormErr).
  * Commits:
    6a790e6 Fix #61: Make sure variables are initialized
    ed37b88 Update Murmur location
    5afb576 Update code format and move Murmur into it's own dir
* Tue Jul 11 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.4.0-1
- Release 1.4.0
  * This release adds new fields for IP version and EDNS0 Client Subnet along
    with documentation updates, new usage (`--help`) and a buffer overflow
    check. Rework of the way OPT records are parsed has been done to make it
    easier to add support for other EDNS options in the future.
  * New fields:
    - `ip_version`: The IP version as an int (4/6)
    - `edns0_ecs`: A bool that is true if Client Subnet (RFC7871) was found
    - `edns0_ecs_family`: An int with the address family
    - `edns0_ecs_source`: An int with the source prefix length
    - `edns0_ecs_scope`: An int with the scope prefix length
    - `edns0_ecs_address`: A textual representation of the address
  * Bugfix:
    - `get_ushort()` in DNS parsing was not checking length of buffer before
      accessing it.
  * Commits:
    0e7c34a Rewrote usage, add option descriptions, tables and fields
    3943dda Update documentation and tests
    f4b9464 Add IP_Version
    0b309e6 ECS addresses and OPT RR parsing
    875fd60 Correct type in documentation also
    b5a91b7 Damn the common keyboard sequences...
    358b9af Buf overflow check, move OPT RR parsing, rework EDNS0 ECS
    d38fffc Add EDNS option codes and EDNS Client Subnet (ECS) support
* Fri Jun 02 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.3.1-1
- Release 1.3.1
  * This release add packaging files for DEB and RPM distributions and
    fixes a couple of bugs:
    - ICMP code to fill the tables was wrong and created segfault using
      normal select, aggregation or group functions. The code has been
      rewritten to work as the DNS code does and ICMP tests have been
      added.
    - Historically PacketQ parses all resource records but only saves
      the first and last record, this would overwrite EDNS information
      if it was not the first or last record. This has been fixed by
      saving the EDNS information as it is found.
  * Thanks to Anand Buddhdev (RIPE NCC) and Daniel Stirnimann (SWITCH)
    for providing PCAPs to help resolve the bugs.
  * Commits:
    9c2627f Fix CID 1439421
    5423c1d Fix #17: Save EDNS information when it's found
    ecb166e Fix #48: ICMP parsing and a little better memory handling
    0052024 Fix #45: Add packaging files
* Tue May 30 2017 Jerry Lundström <lundstrom.jerry@gmail.com> 1.3.0-1
- Release 1.3.0
  * First release under DNS-OARC management with license changed to GPL v3.0,
    minor version jump to not conflict with forked repositories that
    increased the version themselves.
  * Software now using Travis-CI and Jenkins to compile and test under Debian,
    Ubuntu, CentOS, FreeBSD and OpenBSD. Coverity Scan used for code analysis
    and 30 defects have been solved.
  * Bug fixes / enhancements:
    - Big endian supported correctly
    - Check data length when processing TCP/UDP packets
    - Support VLAN-tagged packets
    - Support for older compilers (CentOS 6)
    - Prevent "time of check, time of use"
    - Use `snprintf()` instead of `sprinf()`
  * Commits:
    6782f1f libpcap is not needed
    23a1ca0 Add more 'order by' in tests to ahve concurrent results
    f14ab5d Run tests in Travis also
    1a0c98a Add test for bigendian PCAP
    64ee5a8 - fixed reading of big-endian pcap files (including gzipped pcap)
            - added sample-bigendian.pcap.gz
    dd6ab57 Add test based on the extended regression tests
    27518c5 More regression tests
    d889228 Updated regression-test.sh to make the ordering of test query
            results more consistent, to avoid false positives.
    d157fef Expanded the regression tests.
    b3df6c2 Added checks for bad TCP and UDP packet lengths (which could
            cause malloc requests for humongous amounts of memory...)
    2e46729 Added support for VLAN-tagged ethertypes.
    10ae2d6 Fix #20: Support CentOS 6 compiler (and hopefully RHEL6 also)
    e7a8163 Format code using `clang-format`
    a9ae0fe Change namespace to `packetq` and uniform header defines
    6ab0fde Add Coverity badge
    63b480b Use `open()`, `fstat()` and `fdopen()` to prevent "time of check,
            time of use" problem
    446a5bf Fix CIDs
    01be348 Fix CIDs
    d11a61f Use `snprintf()`
    0bc8e57 Add regression test (from example) for all output formats
    09b9037 Move wiki documentation into the repository
    5e41dbb Update README.md
    6b2263f Add dependencies
    9cd6e5a Add Travis-CI badge
    cf582f8 Add Travis-CI
    d7eaa55 Cleanup and license change
* Wed Apr 23 2014 Roger Murray <undocumented@release> 1.1.11-1
- Release 1.1.11
  * This release and prior releases was not documented here, see repository
    for more information.
