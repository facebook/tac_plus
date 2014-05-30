# Tacacs+ (tac_plus)

C Daemon that authenticates requests via the Tacacs+ Protocol and logs accounting information.

## Requirements
- Linux (have not tested in other OSs)
- tcpwrappers(-devel)
- pam(-devel)

## Default Behavior
There are two spec files tested in CentOS 6. tacacs+6 depends on tacacs+ in order to not duplicate libraries etc.
- tacacs+ logs accounting to syslog and /var/log/tac_plus.acct
- tacacs+6 logs accounting to syslog and /var/log/tac_plus6.acct
- PIDS live in /var/run/tac_plus[6]
- Each binary binds to all addresses for it's protocol (AF_INET: 0.0.0.0 or AF_INET6: ::)
-- This is controlled in the init script
