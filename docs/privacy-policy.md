# Privacy Policy (template)

**Last updated:** fill in before publishing.

> This is a skeleton for the operator to complete and have reviewed by
> counsel. It is not legal advice. Every statement below describes what this
> software does by default. If you change the configuration (for example
> `pqanond --log-clients`, or an upstream resolver that logs), update this
> policy to match.

## What a VPN operator can see

Any VPN operator, including us, is in a position to see the destinations of the
traffic it carries: which addresses you connect to, when, and how much data
moves. Using a VPN moves that visibility from your local network and internet
provider to us. Encrypted traffic (HTTPS) keeps its contents private from us.
Unencrypted traffic does not.

## What we collect

- **Account email** (if you create an account), for login only.
- **Account security log.** Account actions (device enrollment and revocation,
  API keys, staking) are recorded with the time and the IP address that made
  them. You can see your own entries.
- **Aggregate metrics**: counts such as active sessions per server, handshakes
  and bytes carried. These contain no addresses or identifiers.

## What we do not keep

- **Your IP address in VPN server logs.** The tunnel server holds your address
  in memory while your session is active, because it needs it to send your
  traffic back. Its logs name clients only by a pseudonym that changes on every
  restart and can't be reversed.
- **DNS query names.** The server's resolver forwards your lookups without
  logging them. It does send them on to an upstream resolver: fill in which one,
  and its logging policy.
- **Destinations or contents of your traffic.** These are not logged. While a
  connection is open, its addresses are held in the server's in-memory
  connection table for address translation, and they are dropped when it closes.
- **A link between a payment and your usage.** Access bought with blind-signed
  tokens carries no link to the payment, and redemptions are recorded without an
  IP address. See docs/payments.md for the limits of this, such as timing.

## Your rights

Export or delete your account data from the settings page.

## Contact

fill in a contact address before publishing.
