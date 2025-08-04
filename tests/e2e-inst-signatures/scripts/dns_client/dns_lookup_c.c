//go:build ignore
// +build ignore

#define _POSIX_C_SOURCE 200112L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

int main() {
    struct addrinfo hints, *result;
    int status;
    char ip_str[INET_ADDRSTRLEN];
    
    printf("Starting DNS lookup for google.com...\n");
    
    // Clear the hints structure
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;        // IPv4
    hints.ai_socktype = SOCK_DGRAM;   // UDP

    printf("Calling getaddrinfo...\n");
    // Perform DNS lookup for google.com
    status = getaddrinfo("google.com", NULL, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return 1;
    }
    
    printf("getaddrinfo succeeded\n");
    
    // Convert the first result to string (optional, just to verify it worked)
    struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
    if (inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN) == NULL) {
        fprintf(stderr, "inet_ntop error: failed to convert address\n");
        freeaddrinfo(result);
        return 1;
    }
    
    printf("Resolved google.com to: %s\n", ip_str);
    
    // Clean up
    freeaddrinfo(result);
    
    printf("DNS lookup completed successfully\n");
    return 0;
} 