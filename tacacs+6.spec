Summary: TACACS+6 Daemon
Name: tacacs+6
Group: Networking/Servers
Version: FB4.0.4.19.1
Release: 16fb
License: Cisco

Packager: Cooper Lees <cooper@fb.com>
Vendor: Facebook Inc.

Source: tacacs+-%{version}.tar.gz

BuildRoot: %{_tmppath}/tacacs+-%{version}-%{release}-root

BuildRequires: gcc, bison, flex, m4, pam-devel, tcp_wrappers, tcp_wrappers-devel, systemd
Requires: pam, tcp_wrappers, tcp_wrappers-devel, tcp_wrappers-libs, tacacs+

%define _unpackaged_files_terminate_build 0

%description
IPv6 Tacacs+ Daemon for Linux

%debug_package

%prep
umask 022
%{__rm} -rf %{_tmppath}/tacacs+-%{version}-%{release}-root/*
cd %{_builddir}
tar xvzf %{_sourcedir}/tacacs+-%{version}.tar.gz
if [ ! -L %{name}-%{version} ]; then
  ln -s tacacs+-%{version} %{name}-%{version}
fi

%build
pwd
export CFLAGS="-DHAVE_PAM -DIPV6"
cd tacacs+-%{version}
%configure --enable-acls --enable-uenable --with-pidfile=/var/run/tac_plus6.pid --with-acctfile=/var/log/tac_plus6.acct --with-logfile=/var/log/tac_plus6.log --program-suffix=6
%{__make}

%install
export DONT_STRIP=1
%{__rm} -rf %{buildroot}
cd tacacs+-%{version}
%makeinstall
%{__install} -Dp -m0755 tac_plus6.sysvinit %{buildroot}%{_initrddir}/tac_plus6
%{__install} -Dp -m0644 tac_plus6.service %{buildroot}%{_unitdir}/tac_plus6.service
### Clean up buildroot
%{__rm} -f %{buildroot}%{_infodir}/dir

%post
%systemd_post tac_plus6.service

%preun
%systemd_preun tac_plus6.service

%postun
%systemd_postun_with_restart tac_plus6.service

%clean
%{__rm} -rf %{buildroot}

%files

%{_unitdir}/tac_plus6.service
/usr/bin/tac_pwd6
/usr/bin/tac_plus6
/etc/rc.d/init.d/tac_plus6
/usr/share/man/man3/regexp6.3.gz
/usr/share/man/man5/tac_plus.conf6.5.gz
/usr/share/man/man8/tac_plus6.8.gz
/usr/share/man/man8/tac_pwd6.8.gz

%changelog
