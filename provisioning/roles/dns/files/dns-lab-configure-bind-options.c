/*
 * dns-lab-configure-bind-options.c
 *
 * Narrowly-scoped setuid-root helper for Task 2 of the Local DNS Attack Lab.
 * Zero arguments, zero environment dependence, no shell invocation. Writes
 * a fixed options block to /etc/bind/named.conf.options and restarts bind9
 * via a direct execve() with a fixed argv.
 *
 * Install as: owner root:root, mode 4750, group "seed".
 */
#include <stdio.h>
#include <unistd.h>

#define OPTIONS_FILE "/etc/bind/named.conf.options"

static const char *OPTIONS_BLOCK =
    "options {\n"
    "\tdirectory \"/var/cache/bind\";\n"
    "\tdump-file \"/var/cache/bind/dump.db\";\n"
    "\n"
    "\t// DNSSEC is intentionally disabled for this lab so that the\n"
    "\t// spoofing/cache-poisoning attacks in later tasks are not blocked.\n"
    "\t// dnssec-validation auto;\n"
    "\tdnssec-enable no;\n"
    "\n"
    "\tlisten-on { any; };\n"
    "\tallow-query { any; };\n"
    "\trecursion yes;\n"
    "};\n";

int main(void) {
    if (setuid(0) != 0) {
        perror("setuid");
        return 1;
    }

    FILE *f = fopen(OPTIONS_FILE, "w");
    if (!f) {
        perror("fopen");
        return 1;
    }
    if (fputs(OPTIONS_BLOCK, f) == EOF) {
        perror("fputs");
        fclose(f);
        return 1;
    }
    fclose(f);

    char *const argv[] = { "/usr/sbin/service", "bind9", "restart", NULL };
    execv("/usr/sbin/service", argv);

    perror("execv");
    return 1;
}
