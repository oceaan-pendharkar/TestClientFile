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
static void           construct_acc_message(uint8_t *packet, size_t *length, uint8_t packet_type, const char *type);
static void           construct_cht_message(uint8_t *packet, size_t *length, const char *type, int valid);
static void           construct_logout_message(uint8_t *packet, size_t *length, const char *type);
static void           print_response(const uint8_t *response, int length);

#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10
#define SLEEP_LEN 5
#define USERNAME "Testing"
#define PASSWORD "Password123"
#define VERSION 0x03
#define TIMESTAMP "20240301123045Z"
#define MESSAGE "hi"

// values being sent
#define BUFFER_SIZE 1024
#define DEFAULT_SENDER_ID 0x0001
#define INVALID_SENDER_ID 0xFFFF
#define USERNAME_LEN 0x07
#define PASSWORD_LEN 0x0B
#define LOGIN_LENGTH 22
#define CHT_PAYLOAD_LENGTH 30
#define TIMESTAMP_LENGTH 0x0F
#define MESSAGE_LENGTH 0x02

// response packet lengths
#define LOGOUT_FAILURE_LEN 26
#define LOGIN_FAILURE_LEN 45
#define ACC_CREATE_SUCCESS_LEN 9
#define ACC_CREATE_FAILURE_LEN 24
#define LOGIN_SUCCESS_LEN 10
#define CHT_SEND_LEN 36
#define CHT_FAILURE_LEN 26    // should be error code 11 if you're reading this, same length as logout failure's sys err
#define LOGOUT_SUCCESS_LEN 9

// packet type codes
#define ACC_LOGIN 0x0A
#define ACC_CREATE 0x0D
#define ACC_LOGOUT 0X0C
#define CHT_SEND 0x14

// data type codes
#define UTF8_STR 0x0C
#define GENERALIZED_TIME 0x18

int main(int argc, char *argv[])
{
    char                   *address;
    char                   *port_str;
    in_port_t               port;
    struct sockaddr_storage addr;
    uint8_t                 packet[BUFFER_SIZE];
    uint8_t                 logout_sys_err[BUFFER_SIZE];
    uint8_t                 login_failure[BUFFER_SIZE];
    uint8_t                 acc_create_success[BUFFER_SIZE];
    uint8_t                 acc_create_failure[BUFFER_SIZE];
    uint8_t                 login_success[BUFFER_SIZE];
    uint8_t                 cht_send_msg[BUFFER_SIZE];
    uint8_t                 cht_send_sys_err[BUFFER_SIZE];
    uint8_t                 logout_success[BUFFER_SIZE];
    size_t                  length = 0;

    // Flags to track progress
    int sent_logout1      = 0;
    int sent_login1       = 0;
    int sent_create1      = 0;
    int sent_create2      = 0;
    int sent_login2       = 0;
    int sent_chat_valid   = 0;
    int sent_chat_invalid = 0;
    int sent_logout2      = 0;

    address  = NULL;
    port_str = NULL;

    parse_arguments(argc, argv, &address, &port_str);
    handle_arguments(argv[0], address, port_str, &port);
    convert_address(address, &addr);

    while(!(sent_logout1 && sent_login1 && sent_create1 && sent_create2 && sent_login2 && sent_chat_valid && sent_chat_invalid && sent_logout2))
    {
        int     sockfd = socket_create(addr.ss_family, SOCK_STREAM, 0);
        ssize_t bytes_sent;
        ssize_t bytes_received;

        socket_connect(sockfd, &addr, port);

        if(!sent_logout1)
        {
            construct_logout_message(packet, &length, "logout");
            bytes_sent = send(sockfd, packet, length, 0);
            if(bytes_sent == -1)
            {
                perror("send");
                socket_close(sockfd);
                break;
            }
            sleep(1);
            bytes_received = recv(sockfd, logout_sys_err, LOGOUT_FAILURE_LEN + 1, 0);
            if(bytes_received > 0)
            {
                print_response(logout_sys_err, LOGOUT_FAILURE_LEN);
            }
            sent_logout1 = 1;
            socket_close(sockfd);
            continue;
        }

        if(!sent_login1)
        {
            sleep(SLEEP_LEN);
            construct_acc_message(packet, &length, ACC_LOGIN, "login");
            bytes_sent = send(sockfd, packet, length, 0);
            if(bytes_sent == -1)
            {
                perror("send");
                socket_close(sockfd);
                break;
            }
            sleep(1);
            bytes_received = recv(sockfd, login_failure, LOGIN_FAILURE_LEN + 1, 0);
            if(bytes_received > 0)
            {
                print_response(login_failure, LOGIN_FAILURE_LEN);
                sent_login1 = 1;
            }
            socket_close(sockfd);
            continue;
        }

        if(!sent_create1)
        {
            sleep(SLEEP_LEN);
            construct_acc_message(packet, &length, ACC_CREATE, "create");
            bytes_sent = send(sockfd, packet, length, 0);
            if(bytes_sent == -1)
            {
                perror("send");
                socket_close(sockfd);
                break;
            }
            sleep(1);
            bytes_received = recv(sockfd, acc_create_success, ACC_CREATE_SUCCESS_LEN + 1, 0);
            if(bytes_received > 0)
            {
                print_response(acc_create_success, ACC_CREATE_SUCCESS_LEN);
                sent_create1 = 1;
            }
            socket_close(sockfd);
            continue;
        }

        if(!sent_create2)
        {
            sleep(SLEEP_LEN);
            printf("\nsending create a second time...\n");
            bytes_sent = send(sockfd, packet, length, 0);
            if(bytes_sent == -1)
            {
                perror("send");
                socket_close(sockfd);
                break;
            }
            sleep(1);
            bytes_received = recv(sockfd, acc_create_failure, ACC_CREATE_FAILURE_LEN + 1, 0);
            if(bytes_received > 0)
            {
                print_response(acc_create_failure, ACC_CREATE_FAILURE_LEN);
                sent_create2 = 1;
            }
            socket_close(sockfd);
            continue;
        }

        if(!sent_login2)
        {
            sleep(SLEEP_LEN);
            construct_acc_message(packet, &length, ACC_LOGIN, "login");
            bytes_sent = send(sockfd, packet, length, 0);
            if(bytes_sent == -1)
            {
                perror("send");
                socket_close(sockfd);
                break;
            }
            sleep(1);
            bytes_received = recv(sockfd, login_success, LOGIN_SUCCESS_LEN + 1, 0);
            if(bytes_received > 0)
            {
                print_response(login_success, LOGIN_SUCCESS_LEN);
                sent_login2 = 1;
            }
            socket_close(sockfd);
            continue;
        }

        if(!sent_chat_valid)
        {
            sleep(SLEEP_LEN);
            construct_cht_message(packet, &length, "chat send", 1);
            bytes_sent = send(sockfd, packet, length, 0);
            if(bytes_sent == -1)
            {
                perror("send");
                socket_close(sockfd);
                break;
            }
            sleep(1);
            bytes_received = recv(sockfd, cht_send_msg, CHT_SEND_LEN + 1, 0);
            if(bytes_received > 0)
            {
                print_response(cht_send_msg, CHT_SEND_LEN);
                sent_chat_valid = 1;
            }
            socket_close(sockfd);
            continue;
        }

        if(!sent_chat_invalid)
        {
            sleep(SLEEP_LEN);
            construct_cht_message(packet, &length, "invalid chat send", 0);
            bytes_sent = send(sockfd, packet, length, 0);
            if(bytes_sent == -1)
            {
                perror("send");
                socket_close(sockfd);
                break;
            }
            sleep(1);
            bytes_received = recv(sockfd, cht_send_sys_err, CHT_FAILURE_LEN + 1, 0);
            if(bytes_received > 0)
            {
                print_response(cht_send_sys_err, CHT_FAILURE_LEN);
                sent_chat_invalid = 1;
            }
            socket_close(sockfd);
            continue;
        }

        if(!sent_logout2)
        {
            sleep(SLEEP_LEN);
            printf("\nsending logout message again...\n");
            bytes_sent = send(sockfd, packet, length, 0);    // reuse packet
            if(bytes_sent == -1)
            {
                perror("send");
                socket_close(sockfd);
                break;
            }
            sleep(1);
            bytes_received = recv(sockfd, logout_success, LOGOUT_SUCCESS_LEN + 1, 0);
            if(bytes_received > 0)
            {
                print_response(logout_success, LOGOUT_SUCCESS_LEN);
                sent_logout2 = 1;
            }
            socket_close(sockfd);
            continue;
        }

        socket_close(sockfd);
    }
    return EXIT_SUCCESS;
}

static void print_response(const uint8_t *response, int length)
{
    int current_byte = 0;
    printf("\nYour server responded: ");
    while(current_byte < length)
    {
        printf("%02x ", response[current_byte++]);
    }
    printf("\n");
}

static void construct_acc_message(uint8_t *packet, size_t *length, uint8_t packet_type, const char *type)
{
    size_t   offset = 0;
    uint16_t payload_length;
    uint16_t sender_id;

    // Packet type (1 byte)
    packet[offset++] = packet_type;

    // Version (1 byte)
    packet[offset++] = VERSION;    // Version: 2

    // Sender ID (2 bytes) - Using htons() for network byte order
    sender_id = htons(DEFAULT_SENDER_ID);
    memcpy(&packet[offset], &sender_id, 2);
    offset += 2;

    // Payload Length (2 bytes) - Calculated dynamically
    payload_length = htons(LOGIN_LENGTH);
    memcpy(&packet[offset], &payload_length, 2);
    offset += 2;

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

    printf("\nConstructed %s client packet (%zu bytes):\n", type, *length);
    for(size_t i = 0; i < *length; i++)
    {
        printf("%02X ", packet[i]);
    }
    printf("\n");
}

static void construct_logout_message(uint8_t *packet, size_t *length, const char *type)
{
    size_t   offset = 0;
    uint16_t payload_length;
    uint16_t sender_id;

    // Packet type (1 byte)
    packet[offset++] = ACC_LOGOUT;

    // Version (1 byte)
    packet[offset++] = VERSION;    // Version: 2

    // Sender ID (2 bytes) - Using htons() for network byte order
    sender_id = htons(DEFAULT_SENDER_ID);
    memcpy(&packet[offset], &sender_id, 2);
    offset += 2;

    // Payload Length (2 bytes)
    payload_length = htons(0);
    memcpy(&packet[offset], &payload_length, 2);
    offset += 2;

    // Final packet size
    *length = offset;

    printf("\nConstructed %s client packet (%zu bytes):\n", type, *length);
    for(size_t i = 0; i < *length; i++)
    {
        printf("%02X ", packet[i]);
    }
    printf("\n");
}

static void construct_cht_message(uint8_t *packet, size_t *length, const char *type, int valid)
{
    size_t   offset = 0;
    uint16_t payload_length;
    uint16_t sender_id;

    // Packet type (1 byte)
    packet[offset++] = CHT_SEND;

    // Version (1 byte)
    packet[offset++] = VERSION;    // Version: 2

    if(valid == 1)
    {
        // Sender ID (2 bytes) - Using htons() for network byte order
        sender_id = htons(DEFAULT_SENDER_ID);
        memcpy(&packet[offset], &sender_id, 2);
        offset += 2;
    }
    else
    {
        sender_id = htons(INVALID_SENDER_ID);
        memcpy(&packet[offset], &sender_id, 2);
        offset += 2;
    }

    // Payload Length (2 bytes)
    payload_length = htons(CHT_PAYLOAD_LENGTH);
    memcpy(&packet[offset], &payload_length, 2);
    offset += 2;

    // Timestamp
    packet[offset++] = GENERALIZED_TIME;    // Generalized Time type
    packet[offset++] = TIMESTAMP_LENGTH;    // length 15
    for(int i = 0; i < TIMESTAMP_LENGTH; i++)
    {
        packet[offset++] = (uint8_t)TIMESTAMP[i];
    }

    // Content
    packet[offset++] = UTF8_STR;          // UTF8 String type
    packet[offset++] = MESSAGE_LENGTH;    // length 2
    for(int i = 0; i < MESSAGE_LENGTH; i++)
    {
        packet[offset++] = (uint8_t)MESSAGE[i];
    }

    // Username
    packet[offset++] = UTF8_STR;        // UTF8 String type
    packet[offset++] = USERNAME_LEN;    // length 7
    for(int i = 0; i < USERNAME_LEN; i++)
    {
        packet[offset++] = (uint8_t)USERNAME[i];
    }

    // Final packet size
    *length = offset;

    printf("\nConstructed %s client packet (%zu bytes):\n", type, *length);
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
