%global debug_package %{nil}

# tcp_wrappers do not exist on stock EL8/EL9
%define libwrap 0
%define systemd 0

%if 0%{?el6}
%define libwrap 1
%endif
%if 0%{?el7}
%define libwrap 1
%endif
%if 0%{?el8}
%define systemd 1
%endif
%if 0%{?el9}
%define systemd 1
%endif


Summary: TACACS+ Daemon
Name: tacacs
Group: Networking/Servers
Version: F4.0.4.28
Release: 1%{?dist}
License: Cisco

Source: %{name}-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

Requires: pam
BuildRequires: gcc, bison, flex, m4, pam-devel, libtool, autoconf, automake, python-rpm-macros

%if 0%{?libwrap}
BuildRequires: tcp_wrappers, tcp_wrappers-devel
%endif

%if 0%{?systemd}
Requires: systemd
%endif

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

%if 0%{?libwrap}
%configure --enable-acls --enable-uenable
%else
%configure --enable-acls --enable-uenable --without-libwrap 
%endif

%{__make}

%install
export DONT_STRIP=1
%{__rm} -rf %{buildroot}

%makeinstall

%if 0%{systemd}
%{__install} -Dp -m0644 tac_plus.service %{buildroot}%{_unitdir}/tac_plus.service
%else
%{__install} -Dp -m0755 tac_plus.sysvinit %{buildroot}%{_initrddir}/tac_plus
%endif

# no need to do anything on el6
%if 0%{?el7}
%py_byte_compile %{__python} %{buildroot}%{_datadir}/tacacs/do_auth.py
%endif
%if 0%{?el8}
%py_byte_compile %{__python3} %{buildroot}%{_datadir}/tacacs/do_auth.py
%endif
%if 0%{?el9}
%py_byte_compile %{__python3} %{buildroot}%{_datadir}/tacacs/do_auth.py
%endif

### Clean up buildroot
%{__rm} -f %{buildroot}%{_infodir}/dir
%{__rm} -f %{buildroot}%{_libdir}/*.a
%{__rm} -f %{buildroot}%{_libdir}/*.la

%post
%if 0%{?el6}
    /sbin/chkconfig --add tac_plus
%else
%systemd_post tac_plus.service
%endif

%preun
%if 0%{?el6}
  # real uninstall, nothing is left behind
  if [ $1 -eq 0 ] ; then
    /sbin/service tac_plus stop

  fi

%else
%systemd_preun tac_plus.service
%endif

%postun
%if 0%{?el6}
   :
%else
%systemd_postun_with_restart tac_plus.service
%endif

%clean
%{__rm} -rf %{buildroot}

%files

%if 0%{?systemd}
%{_unitdir}/tac_plus.service
%else
%{_initddir}/tac_plus
%endif

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


%{_datadir}/tacacs/do_auth.py
%if 0%{?el6}
%{_datadir}/tacacs/do_auth.pyc
%{_datadir}/tacacs/do_auth.pyo
%endif
%if 0%{?el7}
%{_datadir}/tacacs/do_auth.pyc
%{_datadir}/tacacs/do_auth.pyo
%endif
%if 0%{?el9}
%{_datadir}/tacacs/__pycache__/do_auth.cpython-3*.pyc
%endif

%changelog
* Wed May 17 2023 Kaj Niemi <kajtzu@basen.net> - F4.0.4.28-7fb
- tcpwrappers does not exist on EL9 anymore
- run autoconf, libtool, automake to create everything from scratch
- other small fixes

