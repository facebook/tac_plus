Summary: TACACS+ Daemon
Name: tacacs+
Group: Networking/Servers
Version: F4.0.4.19
Release: 6fb
License: Cisco

Packager: JJ Crawford <jj@fb.com>
Vendor: Shrubbery Networks

Source: %{name}-%{version}.tar.gz
Patch0: tacplus-pam.patch
Patch1: tacplus-logging.patch
Patch2: tacplus-version.patch
Patch3: tacplus-md5pw.patch
Patch4: tacplus-logfac.patch
Patch5: tacplus-noconnect.patch
Patch6: tacplus-logsuc.patch
Patch7: tacplus-logfix.patch

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: gcc, bison, flex, m4, pam-devel, tcp_wrappers, tcp_wrappers-devel
Requires: pam, tcp_wrappers

%description

%prep
%setup
%patch0 -p0
%patch1 -p0
%patch2 -p0
%patch3 -p0
%patch4 -p0
%patch5 -p0
%patch6 -p0
%patch7 -p0

%{__cat} <<'EOF' >tac_plus.sysvinit
#!/bin/bash
#
# /etc/rc.d/init.d/tac_plus
#
# chkconfig: 2345 86 14
# description: TACACS+ Daemon

# Define variables
TACPLUS_PID=/var/run/tac_plus.pid
TACPLUS_BIN=/usr/bin/tac_plus
TACPLUS_OPTS=""
TACPLUS_CONF=/etc/tac_plus.conf

# Source function library.
. /etc/rc.d/init.d/functions

RETVAL=0
prog="tac_plus"

case "$1" in
  start)
        # The process must be configured first.
        [ -f /etc/tac_plus.conf ] || exit 6

        echo -n $"Starting $prog: "
        daemon /usr/bin/tac_plus -C $TACPLUS_CONF $TACPLUS_OPTS
        RETVAL=$?
        [ $RETVAL -eq 0 ] && touch /var/lock/subsys/tac_plus
        echo
        ;;
  stop)
        echo -n $"Shutting down $prog: "
        killproc tac_plus
        RETVAL=$?
        [ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/tac_plus
        echo
        ;;
  restart|reload)
        $0 stop
        $0 start
        RETVAL=$?
        ;;
  condrestart)
        if [ -f /var/lock/subsys/tac_plus ]; then
                $0 stop
                $0 start
        fi
        RETVAL=$?
        ;;
  status)
        status tac_plus
        RETVAL=$?
        ;;
  *)
        echo $"Usage: $0 {start|stop|restart|reload|condrestart|status}"
        exit 2
esac

exit $RETVAL

EOF

%build
%configure --enable-acls --enable-uenable
%{__make}

%install
%{__rm} -rf %{buildroot}
%makeinstall
%{__install} -Dp -m0755 tac_plus.sysvinit %{buildroot}%{_initrddir}/tac_plus
### Clean up buildroot
%{__rm} -f %{buildroot}%{_infodir}/dir

%post

%preun

%clean
%{__rm} -rf %{buildroot}

%files

/usr/include/tacacs.h
/usr/bin/tac_pwd
/usr/bin/tac_plus
/usr/share/tacacs+/users_guide
/usr/share/tacacs+/tac_convert
/usr/share/tacacs+/do_auth.py
/usr/share/tacacs+/do_auth.pyc
/usr/share/tacacs+/do_auth.pyo
/usr/share/man/man5/tac_plus.conf.5.gz
/usr/share/man/man8/tac_pwd.8.gz
/usr/share/man/man8/tac_plus.8.gz
/usr/share/man/man3/regexp.3.gz
/usr/lib64/libtacacs.so.1.0.0
/usr/lib64/libtacacs.so.1
/usr/lib64/libtacacs.so
/usr/lib64/libtacacs.a
/usr/lib64/libtacacs.la
/etc/rc.d/init.d/tac_plus

%changelog
