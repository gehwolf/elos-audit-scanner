# elos audit scanner

The elos audit scanner is an elos plugin, that aims to fetch linux kernel audit
logs directly from the audit netlink interface provided by the kernel.

See https://github.com/linux-audit for more on linux auditing.

It is planed to support two modes :

* unicast - the plugin acts and registers as a audit daemon
* multicast - the plugin just listen on audit events

## build and install

* install elos with plugin support enabled and installed
  (https://elektrobit.github.io/elos/doc/userManual.html#elosd-installation-setup)
* change into elos-audit-scanner source directory
* run `cmake -B build` followed by `make -C build`
* either copy manually via `sudo cp build/scanner_audit.so
  /usr/lib/elos/scanner/` or use `make -C build install`
* create or edit config file in `/etc/elos/scanner/audit.json`, [see](./audit.json)


## run

* run elosd
* subscribe to elos and filter for audit events i.e. `~$ elosc -s ".e.source.appName 'audit' STRCMP"`


## TODO

[] extend parsing and mapping of audit messages into elos events
[] implement `audit` multicast client
[] improve `auditd` implementation

## Requirements

* The plugin shall register on the kernel as audit daemon
* The plugin shall listen to audit massages via unicast in daemon mode
* The plugin shall listen to audit massages via multicast in client mode
* The plugin shall publish received audit-events as elos events

