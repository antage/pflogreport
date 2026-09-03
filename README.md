# pflogreport

A CLI tool in Rust for parsing Postfix mail logs and finding "broken" recipient addresses.

It reads a Postfix syslog, reconstructs each mail message by its queue ID, determines the
final delivery status (`sent`, `deferred`, `bounced`), and classifies delivery failure
reasons into named categories (unknown user, bad MX, DNS failure, over-quota, spam
rejection, blocklists, etc.).

## How it works

1. Every line of the log is parsed as a syslog record:
   `Mon DD HH:MM:SS host program/subsystem[pid]: [msgid:] content`.
2. Lines are grouped into messages by the Postfix message ID (10-12 hex digits that
   postfix prefixes to its log lines).
3. For each message the tool extracts what it can from the relevant subsystems:
   - `postfix/qmgr` — sender (`from=`), size
   - `postfix/smtpd` — client hostname/IP
   - `postfix/cleanup` — RFC 5322 Message-ID
   - `postfix/smtp` — recipient (`to=`) and delivery status
4. The final status of a message is taken from its `postfix/smtp`
   `status=sent|deferred|bounced (reason)` line; the reason text is matched against a
   set of patterns and mapped to a reason category.

## Requirements

- A recent stable Rust toolchain with `cargo` (the project uses Rust 2024 edition, which requires Rust 1.85 or newer).
- No runtime dependencies beyond the standard library.

## Building

```sh
cargo build --release
```

The binary is placed at `target/release/pflogreport`.

## Installation

Either install from the local source with Cargo:

```sh
cargo install --path .
```

or copy the binary to a directory in your `PATH`:

```sh
install -m 0755 target/release/pflogreport /usr/local/bin/
```

## Usage

The log file to analyze is passed as a positional argument:

```sh
pflogreport <command> [OPTIONS] <LOG_FILE>
```

Expected log format (standard Postfix syslog, e.g. from `/var/log/mail.log`):

```
Dec 17 00:02:44 s1 postfix/smtpd[1859960]: connect from host.example.com[192.0.2.240]
Dec 17 00:03:01 s1 postfix/qmgr[1859961]: A1B2C3D4E5: from=<sender@example.com>, size=1234, nrcpt=1 (queue active)
Dec 17 00:03:05 s1 postfix/smtp[1859962]: A1B2C3D4E5: to=<rcpt@example.com>, relay=mx.example.com[192.0.2.34]:25, delay=4, delays=0.01/0.02/0.4/3.5, dsn=5.1.1, status=bounced (host mx.example.com[192.0.2.34] said: 550 5.1.1 <rcpt@example.com>: user not found (in reply to RCPT TO command))
```

### Commands

#### `stats`

Total message counts by final status.

```
$ pflogreport stats data/mail.log
Stats:
	Unknown = 39
	Sent = 610
	Deferred = 8
	Bounced = 10390
```

#### `bounced`

Aggregates delivery failure reasons for bounced messages — this is the primary way to
spot broken addresses.

```
$ pflogreport bounced data/mail.log
All reasons:
	         8 DNSError
	      5466 NoSuchUser
	        40 DisabledUser
	       118 UnsolicitedMessageError
	         7 AccessDenied
	      4745 BadMX
	         6 Other
```

Group by recipient address (the actual broken addresses):

```
$ pflogreport bounced -g addr data/mail.log
Reasons by TO address:
	first@example.com:
		         2 NoSuchUser
	second@example.com:
		         2 NoSuchUser
	third@example.com:
		         2 UnsolicitedMessageError
	...
```

Group by recipient domain (to find broken domains, e.g. domains without MX):

```
$ pflogreport bounced -g domain data/mail.log
Reasons by TO domain:
	mail.example.com:
		      5386 NoSuchUser
	example.com:
		      4743 BadMX
	shop.example.com:
		         2 NoSuchUser
	...
```

Verbose mode prints the full classified reason, including the remote host and IP:

```
$ pflogreport bounced -v data/mail.log
All reasons:
	       198 NoSuchUser { hostname: "mx.example.com", ipaddr: 192.0.2.26 }
	       285 NoSuchUser { hostname: "mx.example.com", ipaddr: 192.0.2.27 }
	         2 DNSError { name: "missing.example.com", _type: "A" }
	...
```

#### `deferred`

Same as `bounced`, but for messages in the deferred queue (temporary failures that are
still being retried).

```
$ pflogreport deferred data/mail.log
All reasons:
	         2 DNSError
	         6 Other
```

### Options

| Option | Applies to | Description |
|---|---|---|
| `-f, --format <fmt>` | all | `json` for machine-readable output; any other value (or default) prints the human-readable console table |
| `-g, --group-by <g>` | `bounced`, `deferred` | `addr` — group by recipient address, `domain` — group by recipient domain; default is no grouping |
| `-v, --verbose` | `bounced`, `deferred` | print the full reason (with remote host/IP) instead of just the reason kind |

#### JSON output

JSON output is a flat structure with counts:

```
$ pflogreport stats -f json data/mail.log
{"unknown":39,"sent":610,"deferred":8,"bounced":10390}

$ pflogreport bounced -f json data/mail.log
[["DNSError",8],["NoSuchUser",5466],["DisabledUser",40],["UnsolicitedMessageError",118],["AccessDenied",7],["BadMX",4745],["Other",6]]

$ pflogreport bounced -f json -g addr data/mail.log
{"second@example.com":[["NoSuchUser",2]],"third@example.com":[["UnsolicitedMessageError",2]],...}
```

Each entry is a `[reason, count]` pair; grouped output maps addresses (or domains) to
their reason lists.

### Reason categories

| Reason | Meaning |
|---|---|
| `DNSError` | Remote host/domain not found in DNS (`Host or domain name not found`) |
| `BadMX` | Domain does not accept mail (nullMX) or mail loops back to itself |
| `ConnectionTimedOut` | TCP connection to the remote MX timed out |
| `ConnectionRefused` | TCP connection to the remote MX was refused |
| `LostConnection` | Connection to the remote host was lost mid-session |
| `NoSuchUser` | `550 5.1.x` — user unknown / no such mailbox (a broken address) |
| `DisabledUser` | `550 5.2.1` — account disabled, frozen or inactive |
| `OverQuotaTemp` | Temporary mailbox quota failure (e.g. `452`/`552` from Gmail) |
| `OverQuotaPerm` | Permanent mailbox quota failure (mailbox full) |
| `UnsolicitedMessageError` | Rejected as unsolicited/spam by the receiving server |
| `AccessDenied` | `550`/`554 Access denied` from the receiving server |
| `CustomDomainPolicy` | Rejected by a domain-level policy (Google gcdp, Microsoft tenant, Apple, etc.) |
| `BlockList` | Sender IP listed on a DNSBL/RBL or has a bad reputation |
| `RelayAccessDenied` | Relay not permitted on the receiving server |
| `BadReverseDNS` | Client hostname has a missing or inconsistent PTR record |
| `Other` | Reason text that did not match any known pattern (raw text is kept) |

## Notes and limitations

- Syslog timestamps do not include the year, so the parser assumes the **current**
  local year for all entries.
- `-f` values other than `json` and `-g` values other than `addr`/`domain` silently
  fall back to the default behavior (console output / no grouping).
- Only `postfix` program lines are analyzed; other daemons in the same log file are
  ignored.
