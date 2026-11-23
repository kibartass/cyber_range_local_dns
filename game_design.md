# Local DNS Attack Lab -- Game Design

Prose version of every level in `training.json`. Adapted from SEED Labs'
*Local DNS Attack Lab* (Wenliang Du) -- see ATTRIBUTION.txt.

## Level 0 -- Welcome (INFO, 0 pts)
Sets the scene: three machines (`user`, `dns`, `attacker`) on one LAN. States
the rule that nothing leaves the sandbox network, that levels are meant to
be done in order, and -- importantly -- explains up front that Levels 5-8's
flags only appear after a *real* network attack is observed, so students
don't waste time hunting for a shortcut that doesn't exist.

## Level 1 -- Access (ACCESS, passkey `start`)
Credentials table for the three machines, and a note that `dns-lab-*`
commands are pre-built, single-purpose helpers rather than general sudo.

## Level 2 -- Task 1: Configure the user machine (2 pts)
Run `dns-lab-set-resolver` on `user` (adds the local DNS server to
`resolvconf`'s head file, which survives DHCP renewals, unlike editing
`/etc/resolv.conf` directly). Confirm with `dig` that the `SERVER:` line in
the output now shows the lab's own DNS server. Answer: the exact
`ip#port` string.

## Level 3 -- Task 2: Stand up BIND9 (2 pts)
Run `dns-lab-configure-bind-options` on `dns` (sets a cache dump-file path
and disables DNSSEC validation, since DNSSEC exists specifically to defeat
the attacks taught later). Answer: the exact directive that disables
DNSSEC.

## Level 4 -- Task 3: Host a zone (2 pts)
Run `dns-lab-configure-zone` on `dns` (declares `example.com` as a master
zone with forward + reverse lookup files). Query it with `+norecurse` and
observe the `aa` flag -- proof the answer is authoritative, not recursive.
Answer: the IP `www.example.com` resolves to.

## Level 5 -- Task 4: Modify the hosts file (2 pts)
The one place a student-chosen value is legitimate: pick any IP, run
`dns-lab-set-hosts-entry <ip>` on `user`, and compare `dig` (ignores
`/etc/hosts`) against `ping` (honors it via NSS). Answer: a short phrase
naming which tool respects the hosts file and which doesn't.

## Level 6 -- Task 5: Direct response spoofing (5 pts, variant flag)
No more hosts-file shortcut: `user` is *not* compromised this time. From
`attacker`, write a Scapy script that sniffs `user`'s outbound query for
`www.example.net` and races back a forged, fully-matching reply (same
transaction ID, question section, swapped src/dst) before any real answer
could arrive -- and in this sandbox, none ever will, since `example.net`
isn't hosted anywhere. Flag appears at `~/flag_task5.txt` on `user` only
once a genuine spoofed packet from `attacker`'s real IP is observed.

## Level 7 -- Task 6: DNS cache poisoning (5 pts, variant flag)
Same spoofing technique, retargeted at `dns`'s own outbound recursive query
instead of the user's, with a long TTL so the forged record sticks in
cache and gets served to every future querent. Flag appears at
`~/flag_task6.txt` on `dns`.

## Level 8 -- Task 7: Authority-section poisoning (5 pts, variant flag)
Extend the Task 6 script with a forged Authority-section NS record
delegating all of `example.net` to `attacker32.com` -- one successful spoof
now controls an entire domain's future lookups, not just one hostname.
Flag appears at `~/flag_task7.txt` on `dns`.

## Level 9 -- Task 8: Extend to a second domain (5 pts, variant flag)
Add a second, unrelated Authority-section NS record for `google.com` onto
the *same* forged reply that answers an `example.net` query -- showing that
successfully spoofing one lookup can be abused to poison records for
domains that were never even queried. Flag appears at `~/flag_task8.txt`
on `dns`.

## Level 10 -- Task 9: Additional-section / bailiwick (2 pts)
Send a reply with three Additional-section glue records: two in-bailiwick
(for names the reply is actually authoritative over) and one completely
unrelated (`www.facebook.com`). Reason about, rather than re-attack, which
ones a well-behaved resolver caches. Answer: "bailiwick".
