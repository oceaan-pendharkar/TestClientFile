#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void           parse_arguments(int argc, char *argv[], char **ip_address, char **port);
static void           handle_arguments(const char *binary_name, const char *ip_address, const char *port_str, in_port_t *port);
static in_port_t      parse_in_port_t(const char *binary_name, const char *port_str);
_Noreturn static void usage(const char *program_name, int exit_code, const char *message);
static void           convert_address(const char *address, struct sockaddr_storage *addr);
static int            socket_create(int domain, int type, int protocol);
static void           socket_connect(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static void           socket_close(int client_fd);
static void           construct_acc_message(uint8_t *packet, size_t *length, uint8_t packet_type);
static void           print_response(const uint8_t *response, int length);

#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10
#define SLEEP_LEN 5
#define USERNAME "Testing"
#define PASSWORD "Password123"

// values being sent
#define BUFFER_SIZE 1024
#define DEFAULT_SENDER_ID 0x0000
#define USERNAME_LEN 0x07
#define PASSWORD_LEN 0x0B
#define LOGIN_LENGTH 22

// response packet lengths
#define LOGIN_FAILURE_LEN 45
#define ACC_CREATE_SUCCESS_LEN 9
#define ACC_CREATE_FAILURE_LEN 24
#define LOGIN_SUCCESS_LEN 10

// packet type codes
#define ACC_LOGIN 0x0A
#define ACC_CREATE 0x0D

// data type codes
#define UTF8_STR 0x0C

int main(int argc, char *argv[])
{
    char                   *address;
    char                   *port_str;
    in_port_t               port;
    int                     sockfd;
    struct sockaddr_storage addr;
    uint8_t                 packet[BUFFER_SIZE];
    uint8_t                 login_failure[BUFFER_SIZE];
    uint8_t                 acc_create_success[BUFFER_SIZE];
    uint8_t                 acc_create_failure[BUFFER_SIZE];
    uint8_t                 login_success[BUFFER_SIZE];
    size_t                  length;
    ssize_t                 bytes_sent;
    ssize_t                 bytes_received;

    address  = NULL;
    port_str = NULL;
    parse_arguments(argc, argv, &address, &port_str);
    handle_arguments(argv[0], address, port_str, &port);
    convert_address(address, &addr);
    sockfd = socket_create(addr.ss_family, SOCK_STREAM, 0);
    socket_connect(sockfd, &addr, port);

    // send login request
    construct_acc_message(packet, &length, ACC_LOGIN);

    bytes_sent = send(sockfd, packet, length, 0);
    if(bytes_sent == -1)
    {
        perror("send");
        close(sockfd);
        return EXIT_FAILURE;
    }

    // receive login failure message
    bytes_received = recv(sockfd, login_failure, LOGIN_FAILURE_LEN + 1, 0);
    if(bytes_received == -1)
    {
        perror("recv");
        close(sockfd);
        return EXIT_FAILURE;
    }

    print_response(login_failure, LOGIN_FAILURE_LEN);

    // send account create message
    construct_acc_message(packet, &length, ACC_CREATE);
    sleep(SLEEP_LEN);
    bytes_sent = send(sockfd, packet, length, 0);
    if(bytes_sent == -1)
    {
        perror("send");
        close(sockfd);
        return EXIT_FAILURE;
    }

    // receive account create success message
    bytes_received = recv(sockfd, acc_create_success, ACC_CREATE_SUCCESS_LEN + 1, 0);
    if(bytes_received == -1)
    {
        perror("recv");
        close(sockfd);
        return EXIT_FAILURE;
    }
    print_response(acc_create_success, ACC_CREATE_SUCCESS_LEN);

    sleep(SLEEP_LEN);
    // send account create message again
    bytes_sent = send(sockfd, packet, length, 0);
    if(bytes_sent == -1)
    {
        perror("send");
        close(sockfd);
        return EXIT_FAILURE;
    }

    // receive account create failure message
    //  01
    //  01
    //  00 00
    //  00 12 (payload length 18)
    //  02 01 0D (Error Code 12)
    //  OC 13 55 73 65 72 20 41 6C 72 65 61 64 79 20 45 78 69 73 74 73 (message: User Already Exists)
    bytes_received = recv(sockfd, acc_create_failure, ACC_CREATE_FAILURE_LEN + 1, 0);
    if(bytes_received == -1)
    {
        perror("recv");
        close(sockfd);
        return EXIT_FAILURE;
    }
    print_response(acc_create_failure, ACC_CREATE_FAILURE_LEN);

    // send login request
    construct_acc_message(packet, &length, ACC_LOGIN);
    sleep(SLEEP_LEN);
    bytes_sent = send(sockfd, packet, length, 0);
    if(bytes_sent == -1)
    {
        perror("send");
        close(sockfd);
        return EXIT_FAILURE;
    }

    // receive login success message
    bytes_received = recv(sockfd, login_success, LOGIN_SUCCESS_LEN, 0);
    if(bytes_received == -1)
    {
        perror("recv");
        close(sockfd);
        return EXIT_FAILURE;
    }

    print_response(login_success, LOGIN_SUCCESS_LEN);

    socket_close(sockfd);

    return EXIT_SUCCESS;
}

static void print_response(const uint8_t *response, int length)
{
    int current_byte = 0;
    printf("response: ");
    while(current_byte < length)
    {
        printf("%02x ", response[current_byte++]);
    }
    printf("\n");
}

static void construct_acc_message(uint8_t *packet, size_t *length, uint8_t packet_type)
{
    size_t   offset = 0;
    uint16_t payload_length;
    uint16_t sender_id;

    // Packet type (1 byte)
    packet[offset++] = packet_type;

    // Version (1 byte)
    packet[offset++] = 0x01;    // Version: 1

    // Sender ID (2 bytes) - Using htons() for network byte order
    sender_id = htons(DEFAULT_SENDER_ID);
    memcpy(&packet[offset], &sender_id, sizeof(sender_id));
    offset += 2;

    // Payload Length (2 bytes) - Calculated dynamically
    payload_length = htons(LOGIN_LENGTH);
    memcpy(&packet[offset], &payload_length, sizeof(payload_length));
    offset += sizeof(payload_length);

    // Username
    packet[offset++] = UTF8_STR;        // UTF8 String type
    packet[offset++] = USERNAME_LEN;    // length 7
    for(int i = 0; i < USERNAME_LEN; i++)
    {
        packet[offset++] = (uint8_t)USERNAME[i];
    }

    // Password
    packet[offset++] = UTF8_STR;        // UTF8 String type
    packet[offset++] = PASSWORD_LEN;    // length 11
    for(int i = 0; i < PASSWORD_LEN; i++)
    {
        packet[offset++] = (uint8_t)PASSWORD[i];
    }

    // Final packet size
    *length = offset;

    printf("Constructed packet (%zu bytes):\n", *length);
    for(size_t i = 0; i < *length; i++)
    {
        printf("%02X ", packet[i]);
    }
    printf("\n");
}

static void parse_arguments(int argc, char *argv[], char **ip_address, char **port)
{
    int opt;

    opterr = 0;

    while((opt = getopt(argc, argv, "h")) != -1)
    {
        switch(opt)
        {
            case 'h':
            {
                usage(argv[0], EXIT_SUCCESS, NULL);
            }
            case '?':
            {
                char message[UNKNOWN_OPTION_MESSAGE_LEN];

                snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                usage(argv[0], EXIT_FAILURE, message);
            }
            default:
            {
                usage(argv[0], EXIT_FAILURE, NULL);
            }
        }
    }

    if(optind + 1 >= argc)
    {
        usage(argv[0], EXIT_FAILURE, "Too few arguments.");
    }

    if(optind < argc - 2)
    {
        usage(argv[0], EXIT_FAILURE, "Too many arguments.");
    }

    *ip_address = argv[optind];
    *port       = argv[optind + 1];
}

static void handle_arguments(const char *binary_name, const char *ip_address, const char *port_str, in_port_t *port)
{
    if(ip_address == NULL)
    {
        usage(binary_name, EXIT_FAILURE, "The ip address is required.");
    }

    if(port_str == NULL)
    {
        usage(binary_name, EXIT_FAILURE, "The port is required.");
    }

    *port = parse_in_port_t(binary_name, port_str);
}

static in_port_t parse_in_port_t(const char *binary_name, const char *str)
{
    char     *endptr;
    uintmax_t parsed_value;

    errno        = 0;
    parsed_value = strtoumax(str, &endptr, BASE_TEN);

    if(errno != 0)
    {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        usage(binary_name, EXIT_FAILURE, "Invalid characters in input.");
    }

    // Check if the parsed value is within the valid range for in_port_t
    if(parsed_value > UINT16_MAX)
    {
        usage(binary_name, EXIT_FAILURE, "in_port_t value out of range.");
    }

    return (in_port_t)parsed_value;
}

_Noreturn static void usage(const char *program_name, int exit_code, const char *message)
{
    if(message)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s [-h] <ip address> <port>\n", program_name);
    fputs("Options:\n", stderr);
    fputs("  -h  Display this help message\n", stderr);
    exit(exit_code);
}

static void convert_address(const char *address, struct sockaddr_storage *addr)
{
    memset(addr, 0, sizeof(*addr));

    if(inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        addr->ss_family = AF_INET;
    }
    else if(inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        addr->ss_family = AF_INET6;
    }
    else
    {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
        exit(EXIT_FAILURE);
    }
}

static int socket_create(int domain, int type, int protocol)
{
    int sockfd;

    sockfd = socket(domain, type, protocol);

    if(sockfd == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

static void socket_connect(int sockfd, struct sockaddr_storage *addr, in_port_t port)
{
    char      addr_str[INET6_ADDRSTRLEN];
    in_port_t net_port;
    socklen_t addr_len;

    if(inet_ntop(addr->ss_family, addr->ss_family == AF_INET ? (void *)&(((struct sockaddr_in *)addr)->sin_addr) : (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr), addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Connecting to: %s:%u\n", addr_str, port);
    net_port = htons(port);

    if(addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        ipv4_addr->sin_port = net_port;
        addr_len            = sizeof(struct sockaddr_in);
    }
    else if(addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        ipv6_addr->sin6_port = net_port;
        addr_len             = sizeof(struct sockaddr_in6);
    }
    else
    {
        fprintf(stderr, "Invalid address family: %d\n", addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if(connect(sockfd, (struct sockaddr *)addr, addr_len) == -1)
    {
        const char *msg;

        msg = strerror(errno);
        fprintf(stderr, "Error: connect (%d): %s\n", errno, msg);
        exit(EXIT_FAILURE);
    }

    printf("Connected to: %s:%u\n", addr_str, port);
}

static void socket_close(int client_fd)
{
    if(close(client_fd) == -1)
    {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}
