#!/bin/bash

SCRIPT_DIR="$(dirname "$0")"
DNS_CLIENT_DIR="$SCRIPT_DIR/dns_client"

clean() {
    rm -f "$DNS_CLIENT_DIR/dns_lookup_c" "$DNS_CLIENT_DIR/dns_iovec_client"
}

exit_err() {
    echo "ERROR: $@"
    # Clean up
    clean
    exit 1
}

# Build DNS lookup C client
gcc -Wall -Wextra -std=c99 -O2 -g -o "$DNS_CLIENT_DIR/dns_lookup_c" "$DNS_CLIENT_DIR/dns_lookup_c.c" -lrt || exit_err "Failed to build dns_lookup_c"

# Build DNS iovec client  
gcc -Wall -Wextra -std=c99 -O2 -g -o "$DNS_CLIENT_DIR/dns_iovec_client" "$DNS_CLIENT_DIR/dns_iovec_client.c" -lrt -lresolv || exit_err "Failed to build dns_iovec_client"

# Run test for simple DNS lookup
"$DNS_CLIENT_DIR/dns_lookup_c" > /dev/null 2>&1 || exit_err "Failed to run DNS lookup C client"

# Run test for DNS request with single node iovec
"$DNS_CLIENT_DIR/dns_iovec_client" google.com 8.8.8.8 --single-iovec > /dev/null 2>&1 || exit_err "Failed to run DNS iovec client"

# Clean up
clean