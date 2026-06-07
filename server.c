#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <sodium.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT        55000
#define SID         "server1"   
#define DATA_BASE   "/srv/secserver"
#define LOG_FILE    "server.log"
#define CERT_FILE   "server.crt"
#define KEY_FILE    "server.key"

#define MAX_PAYLOAD   4096
#define RECV_BUF      8192
#define TOKEN_TTL     300
#define LOCK_TTL      60
#define MAX_FAILS     3
#define RATE_WINDOW   10
#define RATE_MAX      10
#define TOKEN_LEN     32

// Global IP tracking table — persists rate limit and lockout across reconnects
#define MAX_IP_TRACK  256
typedef struct {
    char   ip[INET_ADDRSTRLEN];
    int    fail_count;
    time_t lock_time;
    int    request_count;
    time_t window_start;
} IPRecord;

static IPRecord ip_table[MAX_IP_TRACK];

IPRecord *get_ip_record(const char *ip) {
    for (int i = 0; i < MAX_IP_TRACK; i++) {
        if (strcmp(ip_table[i].ip, ip) == 0)
            return &ip_table[i];
    }
    for (int i = 0; i < MAX_IP_TRACK; i++) {
        if (ip_table[i].ip[0] == '\0') {
            strncpy(ip_table[i].ip, ip, INET_ADDRSTRLEN - 1);
            ip_table[i].window_start = time(NULL);
            return &ip_table[i];
        }
    }
    return NULL;
}

// Logging
void log_event(const char *ip, int port, pid_t pid,
               const char *user, const char *cmd, const char *result)
{
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(f, "%04d-%02d-%02d %02d:%02d:%02d | %s:%d | PID:%d | USER:%s | CMD:%s | %s\n",
            t->tm_year+1900, t->tm_mon+1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec,
            ip, port, (int)pid,
            (user && user[0]) ? user : "NONE",
            cmd, result);
    fclose(f);
}

// TLS response helpers
void tls_send_ok(SSL *ssl, int code, const char *msg) {
    char buf[512];
    snprintf(buf, sizeof(buf), "OK %d SID:%s %s\n", code, SID, msg);
    SSL_write(ssl, buf, strlen(buf));
}

void tls_send_err(SSL *ssl, int code, const char *msg) {
    char buf[512];
    snprintf(buf, sizeof(buf), "ERR %d SID:%s %s\n", code, SID, msg);
    SSL_write(ssl, buf, strlen(buf));
}

// Argon2id password hashing via libsodium
void hash_password(const char *password, char *out_hash) {
    if (crypto_pwhash_str(out_hash,
            password, strlen(password),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        out_hash[0] = '\0';
    }
}

int verify_password(const char *password, const char *hash) {
    return crypto_pwhash_str_verify(hash, password, strlen(password)) == 0;
}

// Replay attack prevention — one-time nonce store
#define MAX_NONCES 512
static char used_nonces[MAX_NONCES][TOKEN_LEN + 1];
static int  nonce_count = 0;

int nonce_seen(const char *nonce) {
    for (int i = 0; i < nonce_count; i++)
        if (strcmp(used_nonces[i], nonce) == 0) return 1;
    return 0;
}

void nonce_store(const char *nonce) {
    if (nonce_count < MAX_NONCES) {
        snprintf(used_nonces[nonce_count], TOKEN_LEN + 1, "%s", nonce);
        nonce_count++;
    } else {
        memmove(used_nonces[0], used_nonces[1], sizeof(used_nonces) - sizeof(used_nonces[0]));
        snprintf(used_nonces[MAX_NONCES - 1], TOKEN_LEN + 1, "%s", nonce);
    }
}

// Session token generation via libsodium
void generate_token(char *out) {
    unsigned char bytes[16];
    randombytes_buf(bytes, sizeof(bytes));
    for (int i = 0; i < 16; i++)
        sprintf(out + i * 2, "%02x", bytes[i]);
    out[32] = '\0';
}

// Username validation — alphanumeric only
int valid_username(const char *u) {
    if (!u || u[0] == '\0') return 0;
    for (int i = 0; u[i]; i++) {
        char c = u[i];
        if (!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')))
            return 0;
    }
    return 1;
}

// User file helpers
void user_file_path(const char *username, char *out, int outsz) {
    snprintf(out, outsz, "%s/users/%s.rec", DATA_BASE, username);
}

int user_exists(const char *username) {
    char path[256];
    user_file_path(username, path, sizeof(path));
    return access(path, F_OK) == 0;
}

int save_user(const char *username, const char *hash) {
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/users", DATA_BASE);
    mkdir(DATA_BASE, 0755);
    mkdir(dir, 0755);
    char path[256];
    user_file_path(username, path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (!f) return 0;
    fprintf(f, "%s\n", hash);
    fclose(f);
    return 1;
}

int load_user_hash(const char *username, char *out, int outsz) {
    char path[256];
    user_file_path(username, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (fgets(out, outsz, f) == NULL) { fclose(f); return 0; }
    out[strcspn(out, "\r\n")] = '\0';
    fclose(f);
    return 1;
}

void create_user_dir(const char *username) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", DATA_BASE, username);
    mkdir(path, 0755);
}

// SIGCHLD — reap zombie children
void handle_sigchld(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// TLS context setup
SSL_CTX *create_tls_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(1); }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }
    return ctx;
}

// Client session handler
void handle_client(SSL *ssl, const char *ip, int port) {
    int    logged_in         = 0;
    char   session_token[33] = "";
    char   logged_user[64]   = "";
    time_t last_active       = time(NULL);
    char   acc[RECV_BUF * 2];
    int    acc_len           = 0;

    IPRecord *ipr = get_ip_record(ip);

    while (1) {
        time_t now = time(NULL);

        // Reset rate limit window per IP
        if (ipr && now - ipr->window_start > RATE_WINDOW) {
            ipr->window_start  = now;
            ipr->request_count = 0;
        }

        // Receive into accumulator
        if (acc_len < (int)sizeof(acc) - 1) {
            int r = SSL_read(ssl, acc + acc_len, sizeof(acc) - 1 - acc_len);
            if (r <= 0) break;
            acc_len += r;
            acc[acc_len] = '\0';
        }

        // Validate LEN: framing
        if (strncmp(acc, "LEN:", 4) != 0) {
            char *next = strstr(acc + 1, "LEN:");
            if (next) {
                int skip = next - acc;
                memmove(acc, next, acc_len - skip);
                acc_len -= skip;
                acc[acc_len] = '\0';
            } else {
                acc_len = 0; acc[0] = '\0';
            }
            tls_send_err(ssl, 400, "Invalid framing");
            log_event(ip, port, getpid(), logged_user, "FRAME", "ERR:invalid framing");
            continue;
        }

        char *newline = memchr(acc, '\n', acc_len);
        if (!newline) continue;

        int plen = 0;
        if (sscanf(acc, "LEN:%d\n", &plen) != 1 || plen < 0) {
            tls_send_err(ssl, 400, "Invalid length value");
            log_event(ip, port, getpid(), logged_user, "FRAME", "ERR:bad length");
            acc_len = 0; acc[0] = '\0';
            continue;
        }

        // Reject oversized payload
        if (plen > MAX_PAYLOAD) {
            tls_send_err(ssl, 413, "Payload too large");
            log_event(ip, port, getpid(), logged_user, "FRAME", "ERR:oversized payload");
            acc_len = 0; acc[0] = '\0';
            continue;
        }

        int header_len = (newline - acc) + 1;
        int need       = header_len + plen;
        if (acc_len < need) continue;

        // Rate limiting per IP
        if (ipr) {
            ipr->request_count++;
            if (ipr->request_count > RATE_MAX) {
                tls_send_err(ssl, 429, "Too many requests");
                log_event(ip, port, getpid(), logged_user, "RATE", "ERR:rate limited");
                memmove(acc, acc + need, acc_len - need);
                acc_len -= need; acc[acc_len] = '\0';
                continue;
            }
        }

        char payload[MAX_PAYLOAD + 1];
        memcpy(payload, acc + header_len, plen);
        payload[plen] = '\0';
        memmove(acc, acc + need, acc_len - need);
        acc_len -= need; acc[acc_len] = '\0';

        char command[64] = "";
        sscanf(payload, "%63s", command);
        now = time(NULL);

        // REGISTER
        if (strcmp(command, "REGISTER") == 0) {
            char user[64], pass[128];
            if (sscanf(payload, "REGISTER %63s %127s", user, pass) != 2) {
                tls_send_err(ssl, 400, "Usage: REGISTER <user> <pass>");
                log_event(ip, port, getpid(), "", "REGISTER", "ERR:bad args");
                continue;
            }
            if (!valid_username(user)) {
                tls_send_err(ssl, 400, "Invalid username (alphanumeric only)");
                log_event(ip, port, getpid(), user, "REGISTER", "ERR:invalid username");
                continue;
            }
            if (user_exists(user)) {
                tls_send_err(ssl, 409, "Username already taken");
                log_event(ip, port, getpid(), user, "REGISTER", "ERR:already exists");
                continue;
            }
            char hash[crypto_pwhash_STRBYTES];
            hash_password(pass, hash);
            if (!save_user(user, hash)) {
                tls_send_err(ssl, 500, "Server error");
                log_event(ip, port, getpid(), user, "REGISTER", "ERR:save failed");
                continue;
            }
            create_user_dir(user);
            tls_send_ok(ssl, 200, "Registered successfully");
            log_event(ip, port, getpid(), user, "REGISTER", "OK");
        }

        // LOGIN
        else if (strcmp(command, "LOGIN") == 0) {
            if (ipr && ipr->fail_count >= MAX_FAILS &&
                now - ipr->lock_time < LOCK_TTL) {
                char msg[64];
                snprintf(msg, sizeof(msg), "Account locked. Try again in %lds",
                         (long)(LOCK_TTL - (now - ipr->lock_time)));
                tls_send_err(ssl, 403, msg);
                log_event(ip, port, getpid(), "", "LOGIN", "ERR:locked");
                continue;
            }
            char user[64], pass[128];
            if (sscanf(payload, "LOGIN %63s %127s", user, pass) != 2) {
                tls_send_err(ssl, 400, "Usage: LOGIN <user> <pass>");
                log_event(ip, port, getpid(), "", "LOGIN", "ERR:bad args");
                continue;
            }
            char stored_hash[crypto_pwhash_STRBYTES];
            if (!load_user_hash(user, stored_hash, sizeof(stored_hash))) {
                tls_send_err(ssl, 401, "Invalid credentials");
                if (ipr) { ipr->fail_count++; if (ipr->fail_count >= MAX_FAILS) ipr->lock_time = now; }
                log_event(ip, port, getpid(), user, "LOGIN", "ERR:user not found");
                continue;
            }
            if (!verify_password(pass, stored_hash)) {
                if (ipr) { ipr->fail_count++; if (ipr->fail_count >= MAX_FAILS) ipr->lock_time = now; }
                tls_send_err(ssl, 401, "Invalid credentials");
                log_event(ip, port, getpid(), user, "LOGIN", "ERR:wrong password");
                continue;
            }
            logged_in = 1;
            if (ipr) ipr->fail_count = 0;
            last_active = now;
            snprintf(logged_user, sizeof(logged_user), "%s", user);
            generate_token(session_token);
            char msg[80];
            snprintf(msg, sizeof(msg), "TOKEN:%s", session_token);
            tls_send_ok(ssl, 200, msg);
            log_event(ip, port, getpid(), user, "LOGIN", "OK");
        }

        // LOGOUT
        else if (strcmp(command, "LOGOUT") == 0) {
            if (!logged_in) {
                tls_send_err(ssl, 403, "Not authenticated");
                log_event(ip, port, getpid(), "", "LOGOUT", "ERR:not logged in");
            } else {
                char saved[64];
                snprintf(saved, sizeof(saved), "%s", logged_user);
                logged_in = 0; session_token[0] = '\0'; logged_user[0] = '\0';
                tls_send_ok(ssl, 200, "Logged out");
                log_event(ip, port, getpid(), saved, "LOGOUT", "OK");
            }
        }

        // Protected commands
        else {
            if (!logged_in) {
                tls_send_err(ssl, 403, "Not authenticated");
                log_event(ip, port, getpid(), "", command, "ERR:not authenticated");
                continue;
            }

            // Session expiry check
            if (now - last_active > TOKEN_TTL) {
                logged_in = 0; session_token[0] = '\0';
                tls_send_err(ssl, 440, "Session expired - please login again");
                log_event(ip, port, getpid(), logged_user, command, "ERR:session expired");
                continue;
            }

            // Token validation
            char tok_field[64] = "";
            sscanf(payload, "%*s %63s", tok_field);
            if (strncmp(tok_field, "TOKEN:", 6) != 0 ||
                strcmp(tok_field + 6, session_token) != 0) {
                tls_send_err(ssl, 403, "Invalid or missing token");
                log_event(ip, port, getpid(), logged_user, command, "ERR:bad token");
                continue;
            }

            // Replay prevention — check one-time nonce
            char nonce[TOKEN_LEN + 1] = "";
            sscanf(payload, "%*s %*s %32s", nonce);
            if (nonce[0] != '\0') {
                if (nonce_seen(nonce)) {
                    tls_send_err(ssl, 403, "Replay attack detected");
                    log_event(ip, port, getpid(), logged_user, command, "ERR:replay detected");
                    continue;
                }
                nonce_store(nonce);
            }

            last_active = now;
            tls_send_ok(ssl, 200, "Command executed");
            log_event(ip, port, getpid(), logged_user, command, "OK");
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    exit(0);
}

// Main — setup TLS server and accept connections
int main(void) {
    if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); exit(1); }

    struct sigaction sa;
    sa.sa_handler = handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    SSL_CTX *ctx = create_tls_context();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); exit(1); }
    if (listen(server_fd, 20) < 0) { perror("listen"); exit(1); }

    printf("[secserver] TLS server listening on port %d\n", PORT);
    fflush(stdout);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t clen = sizeof(client_addr);
        int new_sock = accept(server_fd, (struct sockaddr *)&client_addr, &clen);
        if (new_sock < 0) { perror("accept"); continue; }

        pid_t pid = fork();
        if (pid < 0) { perror("fork"); close(new_sock); continue; }

        if (pid == 0) {
            // Child handles one client
            close(server_fd);
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
            int port = ntohs(client_addr.sin_port);
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, new_sock);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl); close(new_sock); exit(1);
            }
            handle_client(ssl, ip, port);
        }
        // Parent keeps accepting
        close(new_sock);
    }

    SSL_CTX_free(ctx);
    return 0;
}
