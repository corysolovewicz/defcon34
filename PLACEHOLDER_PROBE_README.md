# placeholder_squatting_probe.py

Finds registered placeholder domains that accept mail.

Developers hardcode fake sender domains. `noreply.com`, `donotreply.net`,
`company.us`, whatever the config template shipped with. Those domains are
registrable. If somebody registers one and points a catch-all at it, every piece
of mail the world's misconfigured apps send to that address lands in a stranger's
inbox.

This measures how much of that is out there.

## Install

```
pip install dnspython
pip install colorama     # optional, colourised output
```

## You need a connection that allows outbound port 25

This is the first thing to sort out, because everything else is wasted effort
without it.

**Residential and mobile connections will not work.** Comcast, Spectrum,
CenturyLink, Verizon, every mobile carrier, and phone tethering all block
outbound port 25, and have for years, because that's how they stop infected
machines spewing spam. Most consumer ranges are also on the Spamhaus PBL, which
is the same ISPs saying out loud that nothing in that range should be speaking
SMTP directly.

Plenty of cloud providers block it too, by default and often permanently: AWS EC2
(unlockable by request), Google Cloud (never), Azure (mostly), DigitalOcean and
Vultr (on request, new accounts usually refused). Linode and Hetzner will
generally open it for an account with some history.

The failure mode is the reason this matters. A blocked port 25 doesn't produce an
error you'd notice. Every domain resolves fine, every MX lookup succeeds, and
every SMTP connection times out, so the run completes and reports everything as
`unreachable`. That reads like "nobody out there runs a catch-all", which is the
opposite of what a working run finds.

### Confirm it, don't assume it

```
python placeholder_squatting_probe.py --preflight
```

That checks the four things that decide whether a run is worth starting, and
exits non-zero if it isn't. It probes nothing under study, so it's free to run as
often as you like. A healthy host looks like this:

```
  [+] egress IP    172.234.230.100
  [+] PTR          172-234-230-100.ip.linodeusercontent.com
  [+] FCrDNS       resolves back to 172.234.230.100
  [*] HELO will be 172-234-230-100.ip.linodeusercontent.com
  [+] blocklists   clean on all 4
  [+] port 25      gmail-smtp-in.l.google.com -> 220 mx.google.com ESMTP ...
[+] Ready to probe.
```

Run it first, and again any time the egress IP changes. Because it exits 1 when
the host can't collect usable data, it also works as a guard in a cron entry:

```
python placeholder_squatting_probe.py --preflight && \
python placeholder_squatting_probe.py --exclude-file exclude.txt
```

**Why FCrDNS and not just a PTR.** Receiving MTAs don't only check that reverse
DNS exists, they check that the name it returns resolves *back* to the address
that connected. A PTR failing that is worse than no PTR, because a name that
doesn't match reads as forgery rather than as an unconfigured host. The tool
verifies this and falls back to the address literal `[1.2.3.4]` rather than
present a name it can't stand behind.

Checking by hand, if you'd rather:

```
curl -s https://ipv4.icanhazip.com          # your egress IP
dig -x <ip> +short                          # the PTR
dig +short <ptr-name>                       # must equal <ip>
nc -vz -w5 gmail-smtp-in.l.google.com 25    # outbound 25
```

What works in practice: a VPS from a provider that permits SMTP, with reverse DNS
set on the IP. On Linode that's Networking → the IP → Edit RDNS; most providers
have an equivalent, and it takes a few minutes to propagate. One cheap instance,
torn down afterwards.

## Install

## Run

```
# default sweep: 12 built-in prefixes across 51 TLDs
python placeholder_squatting_probe.py

# one domain
python placeholder_squatting_probe.py --domain noreply.com

# one label across a few TLDs
python placeholder_squatting_probe.py --prefix deleteduser --tlds com,net,us

# the wide list, ~400 labels
python placeholder_squatting_probe.py --prefixes-file prefixes.txt

# skip domains you own
python placeholder_squatting_probe.py --exclude-file exclude.txt
```

Greylisted deferrals get queued automatically. Drain them on a schedule:

```
python placeholder_squatting_probe.py --process-greylist-queue
python placeholder_squatting_probe.py --greylist-queue-status
```

Interrupted sweep:

```
python placeholder_squatting_probe.py --resume
```

## What it does per domain

1. RDAP lookup for registration date and registrar.
2. Resolve MX, falling back to A/AAAA. A null MX (RFC 7505) means the owner
   declined mail, and the probe stops there.
3. `HELO` / `MAIL FROM:<>` / `RCPT TO` against the first MX that answers.
4. If that baseline was accepted, one more `RCPT TO` for an address that cannot
   exist. A 250 to that is a catch-all, and that's the finding.
5. Everything gets written to SQLite.

## Being a good citizen

Sweeping SMTP servers is how you get your IP onto Spamhaus CSS. Three defaults
matter:

**Pacing.** `--delay 2.0`, `--jitter 0.5`, and shuffled domain order so
consecutive probes don't land on the same MX cluster. Volume and rhythm are
what reputation systems score. `--delay 0` exists and you should not use it.

**HELO.** Defaults to the reverse-DNS name of your egress IP, or its `[literal]`
if there's no PTR. An unresolvable HELO is a listing trigger by itself.

**The catch-all gate.** The second probe only fires after the baseline was
accepted. That's the only case where it adds information: it separates a real
`hello@` mailbox from a true catch-all. If the baseline was rejected, the server
already said it won't take this recipient, and a genuine catch-all would have
returned 250 to `hello@` as well. So the gate loses no verdicts, and skipping it
would mean firing guaranteed-invalid recipients at servers that just said no,
which is the directory-harvest pattern.

The run also checks your own egress IP against four DNSBLs before starting and
records the result on the run, so you can throw out data collected from a listed
address. You will want this. A listed IP turns most of your negatives into
"the server didn't like us", which is a different finding entirely.

## Reading the results

Verdicts per domain:

| Verdict | Means |
| :-- | :-- |
| `CATCH-ALL` | Accepted an address that cannot exist. This is the finding. |
| `BLACKHOLE` | Same, but the MX is named blackhole/void/discard. Accepts and drops. |
| `no catch-all` | Recipient genuinely rejected. A real negative. |
| `deferred` | Got a 4xx. No verdict yet, queued for retry. Not a negative. |
| `inconclusive` | Blocked on sender, IP or policy. The recipient was never evaluated. |
| `null MX` | RFC 7505. The owner explicitly declined mail. |
| `parked` | Registered per RDAP, but no mail DNS. Could be pointed at a catch-all any day. |
| `unregistered` | No DNS and no registration record. |

The `deferred` and `inconclusive` distinction matters. Counting either as "no
catch-all" undercounts, and if your IP is listed you will generate a lot of
`inconclusive`.

## Tables

| Table | Contents |
| :-- | :-- |
| `probe_runs` | One row per invocation, with egress IP, DNSBL status, pacing, seed |
| `probe_results` | One row per SMTP attempt. `catch_all_probe=1` is the fake-recipient probe |
| `probe_domain_summary` | One rolled-up row per domain per run. `catch_all_likely=1` is the finding |
| `greylist_queue` | Deferred triplets awaiting retry |
| `v_run_diff` | View: domains whose code or category changed between runs |

Every result carries a `rejection_category`, so the database is answerable in SQL
without regexing SMTP strings after the fact.

```sql
-- catch-alls, newest first
SELECT domain, catch_all_mx, registrar, registration_date
FROM probe_domain_summary WHERE catch_all_likely=1 ORDER BY ts_utc DESC;

-- what changed since the run before
SELECT domain, cat_a, cat_b, code_a, code_b FROM v_run_diff;

-- runs collected from a listed IP, which you probably want to discount
SELECT run_id, ts_utc, egress_ip, dnsbl_listed
FROM probe_runs WHERE dnsbl_listed IS NOT NULL;
```

`v_run_diff` is the interesting one over time. A placeholder that was rejecting
mail last quarter and is accepting it now means somebody just pointed a catch-all
at it.

## A note on RDAP

Registration date and registrar come from RDAP, which is best-effort. The IANA
bootstrap file is fetched once per run and is authoritative; a bundled snapshot
covers the default TLD list when IANA is unreachable.

Some registries answer but publish nothing useful. DENIC (`.de`) returns HTTP 200
with a `last changed` event and no registration date or entities, by policy. `.ch`
is similar. Those come back empty, and that's the registry's decision rather than
a failure.

Others have no public RDAP at all. Those TLDs are deliberately absent from the
snapshot instead of pointing somewhere hopeful, because a wrong entry costs a
full HTTP timeout on every domain in that TLD while a missing one just skips the
lookup. As of this writing that includes `.at`, `.be`, `.cn`, `.co`, `.dk`,
`.es`, `.eu`, `.hu`, `.ir`, `.it`, `.jp`, `.kr`, `.mx`, `.ru`, `.se`, `.tr`,
`.ws` and `.za`.

Either way the SMTP result is the finding. RDAP is context.

## Prefix lists

`DEFAULT_PREFIXES` in the script is twelve labels that turn up over and over in
real config templates and deletion placeholders. That's the shipped default.

`prefixes.txt` is the wide version, roughly 400 labels: bounce and return-path
infrastructure, GDPR erasure placeholders, dev-environment artifacts
(`localhost3000` and friends, which become registrable once you drop the colon),
fictional companies from vendor documentation, and config sentinels like
`yourdomain` and `replaceme`.

It casts a wide net on purpose. Some of those labels are also real, legitimately
used domains: `email`, `user`, `default`, `test`, `example`, `corp`. A hit is not
by itself evidence of anything. Filter on the catch-all verdict and the
registrant data, then look at the domain before you write it up.

## Exclusions

`--exclude-file` skips domains, one per line. If you run catch-all honeypots of
your own, put them here: a sweep that probes your own infrastructure wastes
traffic and drops hits into your results that you already know about.

Copy `exclude.example.txt` to `exclude.txt` and edit it. Keep your real list out
of version control. It's an inventory of your infrastructure.

## Reproducibility

Every run records its seed, delay, jitter and shuffle setting in the run note, so
any run can be replayed with the same `--seed`. Use `--note` to record where you
ran it from. Results from a hotel wifi and results from a clean colo IP are not
the same data, and six months later you will not remember which was which.

## License

GPLv3. Full text in `PLACEHOLDER_PROBE_LICENSE.txt`, which becomes plain
`LICENSE` when this gets split out into its own repo.

In short: you can use, modify and redistribute this, but anything you distribute
that's derived from it has to carry the same licence and ship its source. If you
only run it privately, none of that applies.

Probe domains you have a reason to probe.
