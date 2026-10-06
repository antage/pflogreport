# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), the versions follow semantic
versioning.

## [0.2.0] - 2026-10-06

### Added

- `-` as the log file argument reads the log from stdin, so logs can be piped in without
  a temporary file: `zcat /var/log/mail.log.1.gz | pflogreport bounced -`. A parse error
  now names the source: the file path, or `<stdin>`.

## [0.1.1] - 2026-09-22

### Fixed

- Crash on `postfix/qmgr`, `postfix/smtpd` and `postfix/cleanup` lines that do not carry
  a `field=value` pair.

## [0.1.0] - 2026-09-03

### Added

- `stats`, `bounced` and `deferred` commands that reconstruct messages by queue ID from a
  Postfix mail log and report their final status.
- Console output by default and JSON output with `-f json`; reason grouping by recipient
  address or domain with `-g addr` and `-g domain`; `-v` reports the raw reason text.
- Reason classification for bounced and deferred messages (quota, unknown user, access
  denied, DNS errors, block lists and others); unrecognized reason text is kept as
  `Other`.
- RFC 3339 timestamps next to the classic syslog timestamps.
- Parallel log parsing and message analysis with rayon.
- README with a user guide and build instructions.