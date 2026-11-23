/*
 * dns-lab-configure-zone.c
 *
 * Narrowly-scoped setuid-root helper for Task 3 of the Local DNS Attack Lab.
 * Zero arguments. Appends the example.com forward + reverse zone
 * declarations to named.conf, writes both zone files, and restarts bind9.
 * No shell invocation anywhere.
 *
 * Install as: owner root:root, mode 4750, group "seed".
 */
#include <stdio.h>
#include <unistd.h>

#define NAMED_CONF "/etc/bind/named.conf"
#define FWD_ZONE_FILE "/etc/bind/example.com.db"
#define REV_ZONE_FILE "/etc/bind/192.168.0.db"

static const char *ZONE_DECLS =
    "\nzone \"example.com\" {\n"
    "\ttype master;\n"
    "\tfile \"/etc/bind/example.com.db\";\n"
    "};\n"
    "\nzone \"0.168.192.in-addr.arpa\" {\n"
    "\ttype master;\n"
    "\tfile \"/etc/bind/192.168.0.db\";\n"
    "};\n";

static const char *FWD_ZONE_CONTENT =
    "$TTL 3D\n"
    "@ IN SOA ns.example.com. admin.example.com. (\n"
    "\t\t\t1 ; Serial\n"
    "\t\t\t8H ; Refresh\n"
    "\t\t\t2H ; Retry\n"
    "\t\t\t4W ; Expire\n"
    "\t\t\t1D ) ; Minimum\n"
    "@ IN NS ns.example.com.\n"
    "@ IN MX 10 mail.example.com.\n"
    "www IN A 192.168.0.101\n"
    "mail IN A 192.168.0.102\n"
    "ns IN A 192.168.0.10\n"
    "*.example.com. IN A 192.168.0.100\n";

static const char *REV_ZONE_CONTENT =
    "$TTL 3D\n"
    "@ IN SOA ns.example.com. admin.example.com. (\n"
    "\t\t\t1\n"
    "\t\t\t8H\n"
    "\t\t\t2H\n"
    "\t\t\t4W\n"
    "\t\t\t1D)\n"
    "@ IN NS ns.example.com.\n"
    "101 IN PTR www.example.com.\n"
    "102 IN PTR mail.example.com.\n"
    "10 IN PTR ns.example.com.\n";

static int write_file(const char *path, const char *mode, const char *content) {
    FILE *f = fopen(path, mode);
    if (!f) {
        perror(path);
        return 1;
    }
    if (fputs(content, f) == EOF) {
        perror("fputs");
        fclose(f);
        return 1;
    }
    fclose(f);
    return 0;
}

int main(void) {
    if (setuid(0) != 0) {
        perror("setuid");
        return 1;
    }

    if (write_file(NAMED_CONF, "a", ZONE_DECLS)) return 1;
    if (write_file(FWD_ZONE_FILE, "w", FWD_ZONE_CONTENT)) return 1;
    if (write_file(REV_ZONE_FILE, "w", REV_ZONE_CONTENT)) return 1;

    char *const argv[] = { "/usr/sbin/service", "bind9", "restart", NULL };
    execv("/usr/sbin/service", argv);

    perror("execv");
    return 1;
}
