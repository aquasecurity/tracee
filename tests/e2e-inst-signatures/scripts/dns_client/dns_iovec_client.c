//go:build ignore
// +build ignore

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <resolv.h>
#include <arpa/nameser.h>

// DNS header structure
struct dns_header {
    uint16_t id;          // identification number
    uint16_t flags;       // DNS flags
    uint16_t qdcount;     // number of question entries
    uint16_t ancount;     // number of answer entries
    uint16_t nscount;     // number of authority entries
    uint16_t arcount;     // number of resource entries
};

// DNS question structure
struct dns_question {
    uint16_t qtype;       // question type
    uint16_t qclass;      // question class
};

// Test configuration
#define DNS_SERVER "8.8.8.8"
#define DNS_PORT 53
#define QUERY_DOMAIN "google.com"
#define BUFFER_SIZE 1024
#define TIMEOUT_SEC 5

// Test results structure
struct test_result {
    int passed;
    char error_msg[256];
    double response_time_ms;
    int bytes_sent;
    int bytes_received;
};

// Convert domain name to DNS query format
int domain_to_dns_format(const char* domain, char* dns_format) {
    int len = strlen(domain);
    char* temp = malloc(len + 2);
    strcpy(temp, domain);
    
    int dns_len = 0;
    char* token = strtok(temp, ".");
    
    while (token != NULL) {
        int token_len = strlen(token);
        dns_format[dns_len++] = token_len;
        strcpy(dns_format + dns_len, token);
        dns_len += token_len;
        token = strtok(NULL, ".");
    }
    
    dns_format[dns_len++] = 0; // null terminator for DNS format
    free(temp);
    return dns_len;
}

// Create DNS query packet
int create_dns_query(const char* domain, char* query_buffer) {
    struct dns_header* header = (struct dns_header*)query_buffer;
    
    // Fill DNS header
    header->id = htons(getpid());  // Use process ID as query ID
    header->flags = htons(0x0100); // Standard query with recursion desired
    header->qdcount = htons(1);    // One question
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
    
    // Add question section
    char* question_ptr = query_buffer + sizeof(struct dns_header);
    int domain_len = domain_to_dns_format(domain, question_ptr);
    
    struct dns_question* question = (struct dns_question*)(question_ptr + domain_len);
    question->qtype = htons(1);  // A record
    question->qclass = htons(1); // IN class
    
    return sizeof(struct dns_header) + domain_len + sizeof(struct dns_question);
}

// Send DNS query using iovec
int send_dns_query_iovec(int sockfd, const char* query_buffer, int query_len, 
                        struct sockaddr_in* server_addr, struct test_result* result, int use_single_iovec) {
    
    // Create iovec structures for the DNS query
    struct iovec iov[2];
    struct msghdr msg;
    
    if (use_single_iovec) {
        // Single iovec: entire DNS query in one vector
        iov[0].iov_base = (void*)query_buffer;
        iov[0].iov_len = query_len;
        
        // Setup message structure
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = server_addr;
        msg.msg_namelen = sizeof(struct sockaddr_in);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        
        printf("Using single iovec (%d bytes)\n", query_len);
    } else {
        // Split the DNS query into header and payload for demonstration
        int header_len = sizeof(struct dns_header);
        int payload_len = query_len - header_len;
        
        // First iovec: DNS header
        iov[0].iov_base = (void*)query_buffer;
        iov[0].iov_len = header_len;
        
        // Second iovec: DNS question section
        iov[1].iov_base = (void*)(query_buffer + header_len);
        iov[1].iov_len = payload_len;
        
        // Setup message structure
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = server_addr;
        msg.msg_namelen = sizeof(struct sockaddr_in);
        msg.msg_iov = iov;
        msg.msg_iovlen = 2;
        
        printf("Using dual iovec (header: %d bytes, question: %d bytes)\n", header_len, payload_len);
    }
    
    // Record start time
    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    // Send the DNS query using sendmsg with iovec
    ssize_t bytes_sent = sendmsg(sockfd, &msg, 0);
    
    if (bytes_sent < 0) {
        snprintf(result->error_msg, sizeof(result->error_msg), 
                "Failed to send DNS query: %s", strerror(errno));
        return -1;
    }
    
    result->bytes_sent = bytes_sent;
    if (use_single_iovec) {
        printf("DNS query sent successfully using single iovec (%d bytes)\n", (int)bytes_sent);
    } else {
        printf("DNS query sent successfully using dual iovec (%d bytes)\n", (int)bytes_sent);
        int header_len = sizeof(struct dns_header);
        int payload_len = query_len - header_len;
        printf("  - Header part: %d bytes\n", header_len);
        printf("  - Question part: %d bytes\n", payload_len);
    }
    
    return 0;
}

// Receive and parse DNS response
int receive_dns_response(int sockfd, char* response_buffer, struct test_result* result) {
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        snprintf(result->error_msg, sizeof(result->error_msg), 
                "Failed to set socket timeout: %s", strerror(errno));
        return -1;
    }
    
    // Receive response
    ssize_t bytes_received = recv(sockfd, response_buffer, BUFFER_SIZE, 0);
    
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    
    if (bytes_received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            snprintf(result->error_msg, sizeof(result->error_msg), 
                    "DNS query timeout after %d seconds", TIMEOUT_SEC);
        } else {
            snprintf(result->error_msg, sizeof(result->error_msg), 
                    "Failed to receive DNS response: %s", strerror(errno));
        }
        return -1;
    }
    
    result->bytes_received = bytes_received;
    
    // Calculate response time
    double elapsed = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                    (end_time.tv_nsec - start_time.tv_nsec) / 1000000.0;
    result->response_time_ms = elapsed;
    
    printf("DNS response received (%d bytes) in %.2f ms\n", 
           (int)bytes_received, elapsed);
    
    return bytes_received;
}

// Helper function to extract the first resolved IPv4 address (A record) using libresolv
// Returns 1 if found and copies the IP string to ip_str_out, 0 if not found
int get_first_answer_ip(const char* response_buffer, int response_len, int answer_count, int qdcount, char* ip_str_out, size_t ip_str_out_len) {
    (void)answer_count; // Suppress unused parameter warning
    (void)qdcount;      // Suppress unused parameter warning
    
    ns_msg msg;
    ns_rr rr;
    
    // Parse the DNS message using libresolv
    if (ns_initparse((const unsigned char*)response_buffer, response_len, &msg) != 0) {
        if (ip_str_out && ip_str_out_len > 0) {
            ip_str_out[0] = '\0';
        }
        return 0;
    }
    
    // Get the number of answer records
    int num_answers = ns_msg_count(msg, ns_s_an);
    
    // Look through all answer records for the first A record
    for (int i = 0; i < num_answers; i++) {
        if (ns_parserr(&msg, ns_s_an, i, &rr) != 0) {
            continue; // Skip malformed records
        }
        
        // Check if this is an A record (IPv4)
        if (ns_rr_type(rr) == ns_t_a && ns_rr_class(rr) == ns_c_in) {
            // Ensure we have the right amount of data for IPv4 (4 bytes)
            if (ns_rr_rdlen(rr) == 4) {
                if (ip_str_out && ip_str_out_len > 0) {
                    // Convert the 4-byte IP address to string format
                    inet_ntop(AF_INET, ns_rr_rdata(rr), ip_str_out, ip_str_out_len);
                }
                return 1;
            }
        }
    }
    
    // No A record found
    if (ip_str_out && ip_str_out_len > 0) {
        ip_str_out[0] = '\0';
    }
    return 0;
}

// Parse and validate DNS response using libresolv
int validate_dns_response(const char* response_buffer, int response_len, 
                         uint16_t expected_id, struct test_result* result) {
    
    ns_msg msg;
    
    // Parse the DNS message using libresolv
    if (ns_initparse((const unsigned char*)response_buffer, response_len, &msg) != 0) {
        snprintf(result->error_msg, sizeof(result->error_msg), 
                "Failed to parse DNS response: invalid message format");
        return -1;
    }
    
    // Validate response ID
    uint16_t response_id = ns_msg_id(msg);
    if (response_id != expected_id) {
        snprintf(result->error_msg, sizeof(result->error_msg), 
                "DNS response ID mismatch: expected %d, got %d", 
                expected_id, response_id);
        return -1;
    }
    
    // Check if this is a response (QR flag should be 1)
    if (!ns_msg_getflag(msg, ns_f_qr)) {
        snprintf(result->error_msg, sizeof(result->error_msg), 
                "Invalid DNS response: response flag not set");
        return -1;
    }
    
    // Check response code (RCODE)
    int rcode = ns_msg_getflag(msg, ns_f_rcode);
    if (rcode != ns_r_noerror) {
        snprintf(result->error_msg, sizeof(result->error_msg), 
                "DNS query failed with response code: %d", rcode);
        return -1;
    }
    
    // Check answer count
    int answer_count = ns_msg_count(msg, ns_s_an);
    if (answer_count == 0) {
        snprintf(result->error_msg, sizeof(result->error_msg), 
                "DNS response contains no answers");
        return -1;
    }
    
    printf("DNS response validation successful:\n");
    printf("  - Response ID: %d\n", response_id);
    printf("  - Opcode: %d\n", ns_msg_getflag(msg, ns_f_opcode));
    printf("  - Authoritative: %s\n", ns_msg_getflag(msg, ns_f_aa) ? "yes" : "no");
    printf("  - Truncated: %s\n", ns_msg_getflag(msg, ns_f_tc) ? "yes" : "no");
    printf("  - Recursion Desired: %s\n", ns_msg_getflag(msg, ns_f_rd) ? "yes" : "no");
    printf("  - Recursion Available: %s\n", ns_msg_getflag(msg, ns_f_ra) ? "yes" : "no");
    printf("  - Questions: %d\n", ns_msg_count(msg, ns_s_qd));
    printf("  - Answers: %d\n", answer_count);
    printf("  - Authority: %d\n", ns_msg_count(msg, ns_s_ns));
    printf("  - Additional: %d\n", ns_msg_count(msg, ns_s_ar));

    // Print the answer IP address (if present)
    char ip_str[INET_ADDRSTRLEN];
    if (get_first_answer_ip(response_buffer, response_len, answer_count, ns_msg_count(msg, ns_s_qd), ip_str, sizeof(ip_str))) {
        printf("  - Answer IP Address: %s\n", ip_str);
    } else {
        printf("  - No IPv4 address (A record) found in answers.\n");
    }

    return 0;
}

// Main DNS e2e test function
int run_dns_e2e_test(const char* domain, const char* dns_server, struct test_result* result, int use_single_iovec) {
    int sockfd = -1;
    char query_buffer[BUFFER_SIZE];
    char response_buffer[BUFFER_SIZE];
    
    // Initialize result
    memset(result, 0, sizeof(struct test_result));
    
    printf("Starting DNS e2e test for domain: %s\n", domain);
    printf("Using DNS server: %s:%d\n", dns_server, DNS_PORT);
    
    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        snprintf(result->error_msg, sizeof(result->error_msg), 
                "Failed to create socket: %s", strerror(errno));
        goto cleanup;
    }
    
    // Setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    
    if (inet_pton(AF_INET, dns_server, &server_addr.sin_addr) <= 0) {
        snprintf(result->error_msg, sizeof(result->error_msg), 
                "Invalid DNS server address: %s", dns_server);
        goto cleanup;
    }
    
    // Create DNS query
    int query_len = create_dns_query(domain, query_buffer);
    if (query_len <= 0) {
        snprintf(result->error_msg, sizeof(result->error_msg), 
                "Failed to create DNS query");
        goto cleanup;
    }
    
    // Extract query ID using libresolv for validation
    ns_msg query_msg;
    uint16_t query_id = 0;
    if (ns_initparse((const unsigned char*)query_buffer, query_len, &query_msg) == 0) {
        query_id = ns_msg_id(query_msg);
    }
    printf("Created DNS query (%d bytes) with ID: %d\n", query_len, query_id);
    
    // Send DNS query using iovec
    if (send_dns_query_iovec(sockfd, query_buffer, query_len, &server_addr, result, use_single_iovec) < 0) {
        goto cleanup;
    }
    
    // Receive DNS response
    int response_len = receive_dns_response(sockfd, response_buffer, result);
    if (response_len < 0) {
        goto cleanup;
    }
    
    // Validate DNS response
    if (validate_dns_response(response_buffer, response_len, query_id, result) < 0) {
        goto cleanup;
    }
    
    result->passed = 1;
    printf("DNS e2e test PASSED\n");
    
cleanup:
    if (sockfd >= 0) {
        close(sockfd);
    }
    
    return result->passed ? 0 : -1;
}

// Print test summary
void print_test_summary(struct test_result* result) {
    printf("\n=== DNS E2E Test Summary ===\n");
    printf("Status: %s\n", result->passed ? "PASSED" : "FAILED");
    
    if (!result->passed) {
        printf("Error: %s\n", result->error_msg);
    } else {
        printf("Bytes sent: %d\n", result->bytes_sent);
        printf("Bytes received: %d\n", result->bytes_received);
        printf("Response time: %.2f ms\n", result->response_time_ms);
    }
    printf("============================\n");
}

// Main function
int main(int argc, char* argv[]) {
    const char* domain = QUERY_DOMAIN;
    const char* dns_server = DNS_SERVER;
    int use_single_iovec = 0;  // Default to dual iovec mode

    // Track if domain and dns_server have been set by user
    int domain_set = 0;
    int dns_server_set = 0;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--single-iovec") == 0) {
            use_single_iovec = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [domain] [dns_server] [--single-iovec]\n", argv[0]);
            printf("Options:\n");
            printf("  domain       Domain to query (default: %s)\n", QUERY_DOMAIN);
            printf("  dns_server   DNS server to use (default: %s)\n", DNS_SERVER);
            printf("  --single-iovec   Use single iovec instead of dual iovec\n");
            printf("  --help, -h   Show this help message\n");
            printf("\nExamples:\n");
            printf("  %s                                    # Default test\n", argv[0]);
            printf("  %s google.com                         # Custom domain\n", argv[0]);
            printf("  %s github.com 1.1.1.1                # Custom domain and DNS server\n", argv[0]);
            printf("  %s google.com 8.8.8.8 --single-iovec # Single iovec mode\n", argv[0]);
            return 0;
        } else if (!domain_set) {
            domain = argv[i];
            domain_set = 1;
        } else if (!dns_server_set) {
            dns_server = argv[i];
            dns_server_set = 1;
        }
    }

    printf("DNS E2E Test Script with iovec\n");
    printf("==============================\n");
    printf("Mode: %s\n", use_single_iovec ? "Single iovec" : "Dual iovec");
    
    struct test_result result;
    
    // Run the DNS e2e test
    int ret = run_dns_e2e_test(domain, dns_server, &result, use_single_iovec);
    
    // Print summary
    print_test_summary(&result);
    
    return ret;
}