# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), the versions follow semantic
versioning.

## [Unreleased]

### Added

- The tool is now tested the way it is run: `tests/cli.rs` executes the built binary over a
  small fixture log and checks the reports the README documents, the exit codes and the
  error messages. Counting the fixture by hand is enough to check any expectation in it.
- Reading and analysis are now a library target, and `cargo bench` measures them a function
  at a time: reading one log line, working out what a server's reply means, and putting one
  delivery back together. The new "Hot path" section of the README carries the numbers and
  what they say about where the time actually goes.
- The year of a classic syslog timestamp is inferred from the order of the log. A mail log
  is appended to, so `Jan  1` after `Dec 31` is read as the next year. Before, every such
  line got the year the analysis ran in, which dated the December half of a log read after
  midnight a year late and left a report no wiser. `--year` states the year outright; the
  default anchor is the date of the log file itself, or the clock when reading stdin.
- Two cases the reason classifier did not cover: a reply is tried only against the patterns
  kept for the command it answers, and the unsolicited-message reply carries both the host
  that spoke and the address it blames.

### Changed

- A Postfix queue ID that is not 10-12 hex digits now fails the run with an error naming the
  line. Such a line used to parse without a queue ID, so its lines silently left the message
  they belonged to: a log from a Postfix with 7-digit or longer IDs produced an empty report
  and no complaint.
- Memory is now allocated through mimalloc instead of the system allocator. Reconstructing a
  message costs two or three heap allocations per log line, on rayon threads, and the kernel
  time to serve them was a third of the run: on a 2.26 GB log the whole run went from 8.3 s
  to 6.3 s (-25%, faster in 18 of 18 paired runs; system time 13.5 s to 9.2 s). The price is
  about 160 KB of binary and a C compiler at build time.
- A reason that reads capture groups takes them out of the match, instead of out of a map
  holding every group the matched pattern names. A blocked sender, a lost connection or a
  DNS failure reads one or two groups, so the map cost three to seven allocations on each
  such reply, and about a tenth of all allocations on a reply set shaped like a real log's.
  Working out a reply is 8% quicker; reports are unchanged.
- The bench fixture reaches the reason tables now: 46 of its 94 replies land in a known
  category, and a reply of each of the four kinds of pattern is there, where 90 of 94 used
  to fall through to `Other` unseen. `cargo bench` asserts the mix, so a reply that stops
  matching its pattern fails the bench instead of quietly shrinking what it measures. The
  "Hot path" figures are re-measured on the new fixture.

### Fixed

- The README promised that an unknown `-f` or `-g` value falls back to the default behavior.
  0.3.0 stopped doing that and left the sentence behind.
- `bounced -g addr` and `bounced -g domain` grouped recipients by the exact spelling of the
  address, so one domain written two ways was reported as two (`Mail.ru` next to
  `mail.ru`), while `deferred` folded the whole address and disagreed with `bounced`. The
  domain part is now folded to lowercase once, where the recipient is recorded, and the
  local part is kept as Postfix wrote it, in both commands.

## [0.3.0] - 2026-11-06

### Changed

- The `-f` and `-g` options reject values outside the documented set. `-f xml` and `-g wrong`
  used to silently produce the default report; now they fail with an error naming the accepted
  values, which `--help` lists as well.

### Fixed

- Abort on a log that is not valid UTF-8. Postfix writes SMTP replies as raw bytes, so a
  reply in another encoding (a Chinese MX answering in GBK, for example) used to fail the
  whole run with `stream did not contain valid UTF-8`. Such bytes are now decoded with the
  Unicode replacement character and the line stays in the report.

### Security

- Lockfile update that clears `cargo audit`. `time` 0.1 is gone from the dependency tree
  (RUSTSEC-2020-0071, a potential segfault) since newer chrono no longer pulls it in through
  the unused `oldtime` feature; `anyhow` and `anstream` moved past their unsoundness
  advisories (RUSTSEC-2026-0190 and RUSTSEC-2024-0404).

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