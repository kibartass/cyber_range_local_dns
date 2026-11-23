# Local DNS Attack Lab -- CyberRangeCZ Platform Scenario

Adapted from SEED Labs' *Local DNS Attack Lab* (Wenliang Du). See
`ATTRIBUTION.txt` for full credit and license terms, and `game_design.md`
for the human-readable version of every level.

## Levels and points (30 total, 1-3 pts/hint)

| # | Level | Type | Points | Answer type |
|---|---|---|---|---|
| 0 | Welcome | INFO | - | - |
| 1 | Access | ACCESS | - | passkey `start` |
| 2 | Task 1 -- Configure the user machine | TRAINING | 2 | fixed |
| 3 | Task 2 -- Stand up BIND9 | TRAINING | 2 | fixed |
| 4 | Task 3 -- Host a zone (example.com) | TRAINING | 2 | fixed |
| 5 | Task 4 -- Modify the hosts file | TRAINING | 2 | fixed |
| 6 | Task 5 -- Direct response spoofing | TRAINING | 5 | **variant (APG)** |
| 7 | Task 6 -- DNS cache poisoning | TRAINING | 5 | **variant (APG)** |
| 8 | Task 7 -- Authority-section poisoning | TRAINING | 5 | **variant (APG)** |
| 9 | Task 8 -- Extend to a second domain | TRAINING | 5 | **variant (APG)** |
| 10 | Task 9 -- Additional-section / bailiwick | TRAINING | 2 | fixed |

## Repo layout

```
README.md                      -- this file
game_design.md                 -- prose version of every level
ATTRIBUTION.txt                -- credit + license terms + deviations
LICENSE                        -- MIT for code, SEED's terms for task text
topology.yml                   -- 3 hosts (user, dns, attacker) + router/wan
variables.yml                  -- APG variant-answer definitions
training.json                  -- full level-by-level scenario definition
provisioning/
  playbook.yml                 -- top-level Ansible playbook
  requirements.yml              -- external collections (minimal; see notes)
  host_vars/<host>.yml          -- ansible_python_interpreter: python3
  roles/hosts/tasks/main.yml    -- packages common to every host
  roles/user/...                -- Task 1 + Task 4 helpers, Task 5 watcher
  roles/dns/...                 -- Task 2/3 helpers, Task 6/7/8 watchers
  roles/attacker/...            -- Scapy toolchain, full sudo (see below)
```

Kept **out of this (student-facing) deliverable**, packaged separately:

```
instructor-solutions/
  SOLUTIONS.md                  -- step-by-step answer key for every level
  scripts/                      -- tested(*) reference Scapy attack scripts
```

(*) see "Open items for the user to verify" below -- these were written and
reasoned through carefully but could not be executed end-to-end against a
real multi-VM CyberRangeCZ sandbox from this chat. Test them before you
ship this to students.

## Anti-cheat design

Unlike a lab built around privilege escalation on a locked-down victim, this
lab's student is the *administrator* of two of the three machines (`user`
and `dns`) for the first half of the exercise, and only becomes an
*attacker* against them for the second half. That inversion creates its own
version of the same underlying problem the race-condition lab had:

> If the student still has admin rights over the machine a flag is supposed
> to come from, they can simply fabricate the flag by hand -- edit a zone
> file, add a hosts entry, write a fake cache dump -- without ever
> performing the actual network attack.

The fixes applied here, in the same spirit as the race-condition lab:

1. **No sudo at all** on `user` or `dns`, from the very first provisioning
   step (group membership stripped, `/etc/sudoers.d` scrubbed, `visudo -c`
   re-validated) -- see `roles/user/tasks/main.yml` and
   `roles/dns/tasks/main.yml`.
2. **Every remaining root-requiring setup step** (Tasks 1-3: resolver
   config, BIND options, zone hosting) is done by a **narrowly-scoped
   setuid-root helper binary**, compiled from C (never a shell script --
   Linux ignores the setuid bit on interpreted scripts), that performs
   exactly one hardcoded action and takes **zero attacker-controlled
   input**. These are safe to leave setuid-root permanently because there
   is nothing to parameterize: the DNS server's IP, the BIND options, and
   the zone contents are fixed infrastructure, identical for every student.
3. **Task 4 is the one place a student-chosen value is legitimate** (the
   redirect IP for `www.bank32.com`). Its helper takes exactly one
   argument, validates it strictly as an IPv4 literal with `inet_pton`
   before ever touching the filesystem, never shells out, and hardcodes the
   hostname half of the line -- so there's no injection surface despite
   accepting attacker-controlled input.
4. **Tasks 5-8's flags are APG variant answers, gated behind independent
   network evidence**, not behind anything the student can locally fake.
   A root-owned, non-interactive Scapy watcher (`flag_watcher.py`, deployed
   identically to every sandbox, configured only by Ansible-injected JSON
   the student cannot edit) passively sniffs UDP/53 on the target machine.
   It only copies the pre-generated secret into the student's home
   directory once it observes a DNS **response** packet that (a) physically
   arrived from the attacker machine's real IP and (b) contains a record
   matching that task's expected type/qname/rdata. Since the student has no
   root on the target machine, and the watcher never trusts anything it
   didn't observe arrive over the wire, there is no way to produce the flag
   except by actually sending a forged packet from `attacker`.
5. **`attacker` keeps full, unrestricted sudo.** This is deliberate and
   matches the checklist's own principle: only the machine that IS the
   exploit platform should get broad privilege, and only because it holds
   no secrets worth protecting -- every flag in this lab lives on `user` or
   `dns`, gated as above, never on `attacker`.
6. **Netwox was replaced with Scapy everywhere** it originally appeared
   (Task 5), both for license/availability reasons and so there is exactly
   one toolchain to reason about across Tasks 5-9. See `ATTRIBUTION.txt`.

### Checklist applied (same as the race-condition lab)

- [x] Listed every point in the original lab where the walkthrough assumes
      elevated privilege: Tasks 1, 2, 3 (admin setup) and Task 4
      (`/etc/hosts`).
- [x] For each: could a student reach the end-state without the intended
      step? For 1-3, the "end state" is just a correctly configured DNS
      environment with no secret behind it -- zero-input setuid helpers are
      strictly safer than sudo and change nothing about the exercise. For 4,
      the one validated-argument helper closes the injection surface while
      preserving the one place student choice matters.
- [x] Tasks 5-8's actual secrets are gated behind independently-verifiable
      evidence (a genuinely-arrived spoofed packet), not behind trusting the
      target machine's own state.
- [ ] **Not yet done in this chat: run the full chain end-to-end against a
      real CyberRangeCZ sandbox** (compile the helpers on the actual "seed"
      image, confirm `inet_pton`/libc are present, confirm the reference
      Scapy scripts in `instructor-solutions/scripts/` actually win the
      race against the watcher's sniff filter and BIND's own timeouts, and
      confirm `nscount`/`ancount` handling matches the BIND version your
      image ships). Budget real time for this -- the race-condition lab's
      own notes mention a attack script bug that only showed up when
      actually run.

## Open items for the user to verify

- `topology.yml`'s exact field names/schema (routers/wan/net_mappings/etc.)
  were reconstructed from documented conventions, not copied from a live
  export -- confirm it parses on your platform version.
- `seed` / `mgmt_user: ubuntu` / `m1.medium` need confirming against your
  actual image catalog, same caveat as the reference scenario.
- The setuid helpers assume Debian/Ubuntu paths (`/sbin/resolvconf`,
  `/usr/sbin/service`, `apt`) consistent with the SEED Ubuntu image lineage
  -- confirm these paths exist on whatever "seed" resolves to on your
  platform.
- `requirements.yml` intentionally omits your org's usual external roles
  (sandbox-logging, chrony, user-access, hosts-aliases) since their source
  URLs are platform/org-specific and weren't available in this chat -- add
  them back if your other scenarios' base playbooks expect them.
- The cache-poisoning watchers (Tasks 6-8) assume `example.net` and
  `google.com` never resolve from anywhere else reachable by `dns` (i.e.
  the sandbox has no real path to the public internet, or firewalls UDP/53
  egress). If `dns` CAN reach the real internet, a genuine upstream reply
  for `google.com`'s real NS records could theoretically race the spoof in
  a confusing way for Task 8 -- verify your sandbox's egress policy and
  tighten the WAN/NAT rules in `topology.yml` if needed.

## Deliverables

- `local-dns-attack-lab.zip` -- the student-facing repo (this README
  included), with NO solutions or attack scripts.
- `local-dns-attack-lab-SOLUTIONS.zip` -- `instructor-solutions/`, kept
  separate as per the standard convention for this workflow.
