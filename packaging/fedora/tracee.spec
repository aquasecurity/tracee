Name:		tracee
Version:	VERSION
Release:	RELEASE
License:    Apache-2.0 AND GPL-2.0
Summary:	Security and forensics tool with a runtime detection engine.
BuildRequires:	make
BuildRequires:	elfutils-libelf-devel
BuildRequires:	zlib-devel
BuildRoot:	../../
Packager:	Rafael David Tinoco <rafaeldtinoco@gmail.com>
URL:		https://github.com/aquasecurity/tracee
Source:		/tracee/tracee

%description
Tracee eBPF is a security and forensics tool. It uses Linux eBPF technology to
trace your system and applications at runtime, and analyzes collected events to
detect suspicious behavioral patterns. Use it with tracee-rules to have a
complete security runtime detection system. Tracee rules is a security
detection engine and receives events from Tracee eBPF and, according to defined
signatures (REGO or Golang), warn about suspicious behavior.

%package tracee
Summary: Security and forensics tool.
Requires: elfutils-libelf
Requires: zlib-devel

%description tracee
Tracee eBPF is a security and forensics tool. It uses Linux eBPF technology to
trace your system and applications at runtime, and analyzes collected events to
detect suspicious behavioral patterns.

%package ebpf
Summary: Security and forensics tool.
Requires: elfutils-libelf
Requires: zlib-devel

%description ebpf
Tracee eBPF is a security and forensics tool. It uses Linux eBPF technology to
trace your system and applications at runtime, and analyzes collected events to
detect suspicious behavioral patterns. Use it with tracee-rules to have a
complete security runtime detection system.

%package rules
Summary: Runtime detection engine.
Requires: tracee-ebpf = %{version}-%{release}

%description rules
Tracee rules is a security detection engine and receives events from Tracee
eBPF and, according to defined signatures (REGO or Golang), warn about
suspicious behavior.

# fedora 35, 36 and 37 only, and they don't need btfhub support
%build
make clean
BTFHUB=0 make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_libdir}

# tracee-ebpf
mkdir -m 0755 -p $RPM_BUILD_ROOT/%{_bindir}
install -m 0755 ./dist/tracee-ebpf $RPM_BUILD_ROOT/%{_bindir}

# tracee-rules
mkdir -m 0755 -p $RPM_BUILD_ROOT/%{_bindir}
mkdir -m 0755 -p $RPM_BUILD_ROOT/%{_libdir}/tracee
install -m 0755 ./dist/tracee-rules $RPM_BUILD_ROOT/%{_libdir}/tracee
ln -s %{_libdir}/tracee/tracee-rules $RPM_BUILD_ROOT/%{_bindir}/tracee-rules

# tracee
install -m 0755 ./dist/tracee $RPM_BUILD_ROOT/%{_libdir}/tracee
ln -s %{_libdir}/tracee/tracee $RPM_BUILD_ROOT/%{_bindir}/tracee

# signatures
mkdir -m 0755 -p $RPM_BUILD_ROOT/%{_libdir}/tracee/signatures/
install -m 0644 ./dist/signatures/* $RPM_BUILD_ROOT/%{_libdir}/tracee/signatures/

%clean

%files
%{_bindir}/tracee
%{_libdir}/tracee/tracee
%{_libdir}/tracee/signatures*

%files -n tracee-ebpf
%{_bindir}/tracee-ebpf

%files -n tracee-rules
%{_bindir}/tracee-rules
%{_libdir}/tracee/tracee-rules
%{_libdir}/tracee/signatures*
