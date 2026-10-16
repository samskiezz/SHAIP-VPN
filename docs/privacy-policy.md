# Privacy Policy (template)

**Last updated:** fill in before publishing.

> This is a skeleton for the operator to complete and have reviewed by
> counsel. It is not legal advice. Every statement below describes what this
> software does, and the software has no setting that makes it collect, log or
> keep anything listed under "What we don't keep". If you add something that
> does (a reverse proxy or load balancer that logs requests, an upstream DNS
> resolver that logs queries, a hosting provider's network flow logs, a
> modified build), this policy is no longer true until you say so here.

## The short version

- We don't know who you are. Your account is a random number. We never ask for
  an email address, a name, a phone number or a card.
- We don't log your IP address, when you connect, for how long, how much you
  transfer, the sites you visit or the names you look up.
- You can pay without an account, and the access token you redeem can't be
  linked to the payment that bought it.
- You can delete your account at any time. Everything stored about it goes.

## What any VPN operator can see, us included

While you are connected, the VPN server you use necessarily handles:

- **Your IP address**, because it has to send your traffic back to you.
- **Where your traffic goes, when, and how much.** Using a VPN moves that
  visibility from your local network and internet provider to the VPN
  operator; it doesn't remove it. Encrypted traffic (HTTPS) keeps its contents
  private from us. Unencrypted traffic does not.
- **Your device's public key**, because that is how the server knows to let
  you in.

The server software holds these in memory only, for as long as your session
lasts, and writes none of them anywhere (see below). You are trusting that the
servers run this software unmodified, as you trust any VPN operator.

## What we keep

This is everything. Times on these records are the calendar day (UTC), never
the moment, so they can't be lined up against network records kept elsewhere
to tie an account to an address.

- **Your account:** a random 16-digit account number, an Argon2id hash of
  your password, and the day it was created.
- **Devices you enroll:** the platform (iPhone, iPad, Android, Windows, Linux,
  Mac, or just "device"), the device's public key, a random device id, the day
  it was enrolled, its certificate's expiry and, if you revoke it, the day you
  did. Never the device's name: our apps send only the platform.
- **API keys you create:** the label you type (stored as you type it, so don't
  put anything personal in it), a hash of the key, and the day.
- **Your account's security log:** what was done (a device enrolled or revoked,
  an API key created or deleted) and on which day. Never from where. Only you
  can see it.
- **Payments:** an order holds the plan, the payment address it was given, the
  blinded tokens (which can't be linked to the tokens you later redeem), and
  the days it was opened and paid. A redeemed token leaves a hash of its
  one-time value (so it can't be spent twice) and the day.
- **Revoked devices:** the ids of revoked devices are published to our servers
  so they refuse them, until their certificates expire.
- **Aggregate counters** for running the service: numbers such as sessions
  active, handshakes, bytes carried per server, and orders and redemptions per
  plan. They contain no address or identifier. On a server with very few
  users, an aggregate count reflects those few users' activity; the counters
  are kept on a private network and never published.

## What we don't keep

- **Your IP address.** It is not written to any log, database or file, by the
  VPN servers or by the account and payment service. The account service
  doesn't read it at all and has no request log. Every log line our servers
  write passes through a filter that removes any IP address, as a backstop.
- **Connection logs.** No record of when you connected, from where, for how
  long or how much you transferred. The VPN servers write no line per session.
- **Your traffic or its destinations.** While a connection is open, the
  server's kernel keeps its addresses for address translation (NAT). When your
  tunnel address is released, about ten minutes after you disconnect, those
  entries are deleted.
- **DNS queries.** The server's resolver forwards your lookups without logging
  them. It does send them on to an upstream resolver: fill in which one, and
  its logging policy.
- **Your email, name, phone number or payment card.** We never ask for them. A
  registration that sends one anyway has it ignored.
- **The name of your device or computer.**
- **A link between a payment and your use of the VPN.** See "Payments".

## Payments

You don't need an account to pay, and you never give a name or email. You pay
for access tokens with Monero or Bitcoin; the tokens are blind-signed (RFC
9474), so the token you redeem carries nothing that links it to the order that
paid for it, and redeeming records nothing but the hash and the day above.

The limits are real, and docs/payments.md describes them: if you buy and
connect from the same network at about the same time, timing can suggest a
link; a Bitcoin payment is public on its blockchain; and paying straight from
an exchange account that knows your identity links that payment to you.

## Third parties

- **No analytics, advertising, trackers, crash reporting, CDNs or third-party
  fonts** in our apps or website. They contact only our servers.
- **Our hosting providers** can see that an address exchanged traffic with our
  servers, as any network can, and may keep their own records of that. Fill
  in your providers and what they say they keep.
- **Payment networks.** Monero and Bitcoin payments go to wallets we run
  ourselves (a Monero wallet, or a self-hosted BTCPay Server). The blockchains
  themselves are public.
- **Third-party servers.** If the network includes VPN servers run by other
  operators, a server you connect through can see what any VPN operator can
  see (above) while you are connected to it. Your device certificate tells it
  nothing about your account.

## On your devices

- **The iPhone app** sends only "iPhone" or "iPad" as the device's name, shows
  no server or address on the lock screen, hides its screen from the app
  switcher, marks its system log details private, and keeps your device keys
  out of iCloud and computer backups.
- **The command-line client** keeps its status file readable by root only.

## Your account and your rights

- **See what we hold:** your account page, device list, API keys and security
  log show everything stored about your account.
- **Delete your account:** from your account page, with your password. Your
  account, devices, API keys and security log are erased. Your enrolled
  devices' ids stay on the revocation list until their certificates expire,
  so a stolen device can't keep using them.
- **There is no account recovery.** Because we don't know who you are, we
  can't send you a lost account number or reset a password. Keep them safe.

## Upgrading an existing installation (operators)

Earlier versions of this software collected data this policy says we don't
keep: account email addresses, IP addresses in the account security log,
request logs with client IP addresses, per-account connection records,
per-account domain rules and settings, device names, and exact times. When a
control plane at this version starts on such a database, it removes all of it
and rewrites the affected tables so the data is gone from their files.

- Accounts that existed before are given a random account number that nobody
  has been told, so they can't log in. If you have real users, run this
  before upgrading, and give each user their number through a channel you
  already have with them; then destroy the output:
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS account_number TEXT UNIQUE;`
  `UPDATE users SET account_number = lpad(((('x' || encode(gen_random_bytes(8), 'hex'))::bit(64)::bigint & 9223372036854775807) % 10000000000000000)::text, 16, '0') WHERE account_number IS NULL;`
  `SELECT email, account_number FROM users;`
- Backups, database dumps, WAL archives and log files made before the upgrade
  still contain the old data. Destroy them, and delete old control-plane and
  pqanond logs.

## Contact

fill in a contact address before publishing. Never ask a customer for an
email address to answer them; they can write from any address they choose.
