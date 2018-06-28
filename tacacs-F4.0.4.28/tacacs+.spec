Summary: TACACS+ Daemon
Name: tacacs+
Group: Networking/Servers
Version: F4.0.4.28
Release: 1.jw
License: Cisco

Packager: Bruce Carleton <bruce.carleton@jasperwireless.com>
Vendor: Cisco

Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: gcc, bison, flex, m4, pam-devel
Requires: pam

%description

%prep
%setup

%{__cat} <<'EOF' >tac_plus.sysvinit
#!/bin/bash
#
# /etc/rc.d/init.d/tac_plus
#
# chkconfig: 2345 86 14
# description: TACACS+ Daemon

# Define variables
TACPLUS_PID=/var/run/tac_plus.pid
TACPLUS_EXE=/usr/bin/tac_plus
TACPLUS_ARG=""
TACPLUS_CNF=/etc/tac_plus.conf

# Source function library.
. /etc/rc.d/init.d/functions

case "$1" in
start)
# Check to see if tac_plus is running.
if [[ -f ${TACPLUS_PID} || -f /var/lock/subsys/tac_plus ]]; then
	echo "tac_plus may already be running. Check for existing tac_plus processes."
	exit 1
fi
echo -n "Starting tac_plus:"
$TACPLUS_EXE $TACPLUS_ARG -C $TACPLUS_CNF && success || failure
echo
touch /var/lock/subsys/tac_plus
;;
stop)
if [[ -f ${TACPLUS_PID} && -f /var/lock/subsys/tac_plus ]]; then
	echo -n "Stopping tac_plus:"
	killproc -p ${TACPLUS_PID}
	echo
	rm -f /var/lock/subsys/tac_plus
	rm -f ${TACPLUS_PID}
else
	echo "tac_plus does not appear to be running."
fi
;;
status)
if [[ -f ${TACPLUS_PID} && -f /var/lock/subsys/tac_plus ]]; then
       echo "tac_plus pid is `cat ${TACPLUS_PID}`"
else
        echo "tac_plus does not appear to be running."
fi
;;
restart)
$0 stop; $0 start
;;
reload)
echo -n "Reloading tac_plus..."
if [[ -f ${TACPLUS_PID} && -f /var/lock/subsys/tac_plus ]]; then
	kill -HUP `cat ${TACPLUS_PID}`
	RETVAL=$?
fi
if [ $RETVAL -ne 0 ]; then
	failure
else
	success
fi
echo

;;
*)
echo "Usage: $0 {start|stop|status|reload|restart}"
exit 1
;;
esac
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
/usr/share/man/man5/tac_plus.conf.5.gz
/usr/share/man/man8/tac_pwd.8.gz
/usr/share/man/man8/tac_plus.8.gz
/usr/share/man/man3/regexp.3.gz
/usr/lib/libtacacs.so.1.0.0
/usr/lib/libtacacs.so.1
/usr/lib/libtacacs.so
/usr/lib/libtacacs.a
/usr/lib/libtacacs.la
/etc/rc.d/init.d/tac_plus

%changelog
