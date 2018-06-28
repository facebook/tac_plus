# Tacacs+ (tac_plus)

C Daemon that authenticates requests via the Tacacs+ Protocol and logs accounting information.

This is a fork of Cisco + Shruberry's Tacacas+ daemons (http://www.shrubbery.net/tac_plus/)

## Requirements
- Linux (have not tested in other OSs)
- tcpwrappers(-devel)
- pam(-devel)

## Supports
- IPv4 + IPv6
- RPM Spec Files included
- SystemD .service files
- PAM Support
- tcpwrappers support
- Syslog Logging

## Default Behavior
There are two spec files tested in CentOS 6. tacacs+6 depends on tacacs+ in order to not duplicate libraries etc.
- tacacs+ logs accounting to syslog and /var/log/tac_plus.acct
- tacacs+6 logs accounting to syslog and /var/log/tac_plus6.acct
- PIDS live in /var/run/tac_plus[6]
- Each binary binds to all addresses for its address family (AF_INET: 0.0.0.0 or AF_INET6: ::)
-- This is controlled in the unit file

## INSTALLING
Buid from source (./configure ; make ; make install)
- For IPv6 you will need CFLAGS="-DIPV6":
or build an RPM
- rpmbuild -ba tacacs+[6].spec
-- tacacs+6 requires tacacs+ for libraries with default specfiles (easily changeable if you want IPV6 only)

### RPM Build
- git clone git@github.com:facebook/tac_plus.git
- cd tac_plus
- mkdir -p ~/rpmbuild/SOURCES
- tar cvzf ~/rpmbuild/SOURCES/tacacs+-FB4.0.4.19.1.tar.gz src
- echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
- sudo yum install rpm-build redhat-rpm-config gcc bison flex m4 pam-devel tcp_wrappers tcp_wrappers-devel
- rpmbuild -ba tacacs+.spec
- rpmbuild -ba tacacs+6.spec

- Have a beer 🍺
