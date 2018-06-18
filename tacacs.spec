Summary: TACACS+ Daemon
Name: tacacs
Group: Networking/Servers
Version: F4.0.4.28
Release: 6fb
License: Cisco

Packager: Facebook Networking <neteng@fb.com> 
Vendor: Facebook Inc.

Source: %{name}-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: gcc, bison, flex, m4, pam-devel, tcp_wrappers, tcp_wrappers-devel, systemd, python
Requires: pam, tcp_wrappers, tcp_wrappers-devel, tcp_wrappers-libs

%description
Tacacs+ Daemon for Linux

%prep
%setup

%build
export CFLAGS="-DHAVE_PAM"
%configure --enable-acls --enable-uenable
%{__make}

%install
export DONT_STRIP=1
%{__rm} -rf %{buildroot}
%makeinstall
%{__install} -Dp -m0755 tac_plus.sysvinit %{buildroot}%{_initrddir}/tac_plus
%{__install} -Dp -m0644 tac_plus.service %{buildroot}%{_unitdir}/tac_plus.service
### Clean up buildroot
%{__rm} -f %{buildroot}%{_infodir}/dir

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
/usr/include/tacacs.h
/usr/bin/tac_pwd
/usr/sbin/tac_plus
/usr/share/tacacs/users_guide
/usr/share/tacacs/tac_convert
/usr/share/tacacs/do_auth.py
/usr/share/tacacs/do_auth.pyc
/usr/share/tacacs/do_auth.pyo
/usr/share/man/man5/tac_plus.conf.5.gz
/usr/share/man/man8/tac_pwd.8.gz
/usr/share/man/man8/tac_plus.8.gz
%{_libdir}/libtacacs.so.1.0.0
%{_libdir}/libtacacs.so.1
%{_libdir}/libtacacs.so
%{_libdir}/libtacacs.a
%{_libdir}/libtacacs.la
/etc/rc.d/init.d/tac_plus

%changelog
