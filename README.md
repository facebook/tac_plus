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
- tacacs+ logs accounting to syslog and /var/log/tac_plus.acct
- PIDS live in /var/run/tac_plus

## INSTALLING
Build from source (./configure ; make ; make install)
or build an RPM
- rpmbuild -ba tacacs.spec

### RPM Build
- git clone git@github.com:facebook/tac_plus.git
- cd tac_plus
- mkdir -p ~/rpmbuild/SOURCES
- tar cvzf ~/rpmbuild/SOURCES/tacacs-F4.0.4.28.tar.gz tacacs-F4.0.4.28
- echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
- sudo yum install rpm-build redhat-rpm-config gcc bison flex m4 pam-devel tcp_wrappers tcp_wrappers-devel
- rpmbuild -ba tacacs.spec
- Have a beer 🍺

## License
tac_plus is BSD licensed, as found in the LICENSE file.
