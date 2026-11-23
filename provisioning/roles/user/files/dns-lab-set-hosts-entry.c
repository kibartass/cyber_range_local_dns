/*
 * dns-lab-set-hosts-entry.c
 *
 * Narrowly-scoped setuid-root helper for Task 4 of the Local DNS Attack Lab.
 *
 * This is the ONE step in the lab where a student-chosen value is
 * legitimately part of the exercise (the redirect target IP for
 * www.bank32.com). To keep that without handing out general sudo:
 *
 *   - Exactly one argument is accepted: an IPv4 address literal.
 *   - It is validated with inet_pton(AF_INET, ...) -- if it doesn't parse
 *     as a clean dotted-quad IPv4 address, the program refuses and exits.
 *   - The validated value is written with fprintf() directly into
 *     /etc/hosts; there is no system()/popen()/shell invocation anywhere
 *     in this program, so there is no shell-metacharacter injection
 *     surface even though the input is attacker-controlled.
 *   - The hostname half of the line ("www.bank32.com") is hardcoded, not
 *     taken from argv, so a student cannot repoint an arbitrary hostname.
 *
 * Install as: owner root:root, mode 4750, group "seed".
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HOSTS_FILE "/etc/hosts"
#define TARGET_HOSTNAME "www.bank32.com"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <ipv4-address>\n", argv[0]);
        return 1;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, argv[1], &addr) != 1) {
        fprintf(stderr, "refusing: '%s' is not a valid IPv4 address\n", argv[1]);
        return 1;
    }

    /* Re-render through inet_ntop so only the parsed, canonical form is
     * ever written -- never the raw argv string. */
    char canonical[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &addr, canonical, sizeof(canonical))) {
        perror("inet_ntop");
        return 1;
    }

    if (setuid(0) != 0) {
        perror("setuid");
        return 1;
    }

    FILE *f = fopen(HOSTS_FILE, "a");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fprintf(f, "%s %s\n", canonical, TARGET_HOSTNAME);
    fclose(f);

    printf("Added: %s %s\n", canonical, TARGET_HOSTNAME);
    return 0;
}
