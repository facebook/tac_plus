%global debug_package %{nil}

Summary: TACACS+ Daemon
Name: tacacs
Group: Networking/Servers
Version: F4.0.4.28
Release: 1%{?dist}
License: Cisco

Source: %{name}-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: gcc, bison, flex, m4, pam-devel, systemd, libtool, autoconf, automake, python-rpm-macros
Requires: pam

%description
Tacacs+ Daemon for Linux

%prep
%setup

%build
export CFLAGS="-DHAVE_PAM"

libtoolize --force
autoreconf --install
automake --add-missing
autoreconf

export CFLAGS="-fPIE"

%configure --enable-acls --enable-uenable --without-libwrap 
%{__make}

%install
export DONT_STRIP=1
%{__rm} -rf %{buildroot}
%makeinstall
# %{__install} -Dp -m0755 tac_plus.sysvinit %{buildroot}%{_initrddir}/tac_plus
%{__install} -Dp -m0644 tac_plus.service %{buildroot}%{_unitdir}/tac_plus.service

%py_byte_compile %{__python3} %{buildroot}%{_datadir}/tacacs/do_auth.py

### Clean up buildroot
%{__rm} -f %{buildroot}%{_infodir}/dir
%{__rm} -f %{buildroot}%{_libdir}/*.a
%{__rm} -f %{buildroot}%{_libdir}/*.la

%post
%systemd_post tac_plus.service

%preun
%systemd_preun tac_plus.service

%postun
%systemd_postun_with_restart tac_plus.service

%clean
%{__rm} -rf %{buildroot}

%files

%{_unitdir}/tac_plus.service
%{_includedir}/tacacs.h
%{_bindir}/tac_pwd
%{_sbindir}/tac_plus
%{_datadir}/tacacs/users_guide
%{_datadir}/tacacs/tac_convert
%{_mandir}/man5/tac_plus.conf.5.gz
%{_mandir}/man8/tac_pwd.8.gz
%{_mandir}/man8/tac_plus.8.gz
%{_libdir}/libtacacs.so.1.0.0
%{_libdir}/libtacacs.so.1
%{_libdir}/libtacacs.so
#/etc/rc.d/init.d/tac_plus

%{_datadir}/tacacs/do_auth.py
%{_datadir}/tacacs/__pycache__/do_auth.cpython-3*.pyc

%changelog
* Wed May 17 2023 Kaj Niemi <kajtzu@basen.net> - F4.0.4.28-7fb
- tcpwrappers does not exist on EL9 anymore
- run autoconf, libtool, automake to create everything from scratch
- other small fixes

