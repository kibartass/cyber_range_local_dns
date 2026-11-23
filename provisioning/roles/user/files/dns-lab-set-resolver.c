/*
 * dns-lab-set-resolver.c
 *
 * Narrowly-scoped setuid-root helper for Task 1 of the Local DNS Attack Lab.
 *
 * Design: takes ZERO command-line arguments, reads NO environment
 * variables, never calls system()/exec() of any kind, and performs exactly
 * one hardcoded action: append a fixed nameserver line to the resolvconf
 * head file, then re-run `resolvconf -u` via a direct, fully-qualified
 * execve() with a fixed argv (no shell involved, nothing attacker-
 * controlled passes through it).
 *
 * This exists so the student never needs general sudo on this machine: the
 * action it performs is identical for every student (the DNS server's IP
 * is fixed infrastructure, not a secret or a choice), so there is nothing
 * to parameterize and nothing to exploit.
 *
 * Install as: owner root:root, mode 4750, group "seed" (so only the lab
 * user can execute it).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#define HEAD_FILE "/etc/resolvconf/resolv.conf.d/head"
#define NAMESERVER_LINE "nameserver 192.168.0.16\n"

int main(void) {
    if (setuid(0) != 0) {
        perror("setuid");
        return 1;
    }

    FILE *f = fopen(HEAD_FILE, "a");
    if (!f) {
        perror("fopen");
        return 1;
    }
    if (fputs(NAMESERVER_LINE, f) == EOF) {
        perror("fputs");
        fclose(f);
        return 1;
    }
    fclose(f);

    /* Fixed argv, fixed path, no shell. */
    char *const argv[] = { "/sbin/resolvconf", "-u", NULL };
    execv("/sbin/resolvconf", argv);

    /* Only reached if execv failed. */
    perror("execv");
    return 1;
}
