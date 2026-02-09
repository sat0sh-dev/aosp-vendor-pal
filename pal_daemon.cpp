#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>

#include <cstring>
#include <cerrno>
#include <string>

// マルチキャスト設定
constexpr const char* MULTICAST_GROUP = "239.255.0.1";
constexpr int MULTICAST_PORT = 12345;
constexpr int BUFFER_SIZE = 1024;

// Phase 3.7: Data Broker UDS設定（trust-based authentication）
constexpr const char* DB_SOCKET_PATH = "/data/misc/db/data_broker.sock";

/**
 * Data BrokerへUDS接続してSETコマンドを送信
 * Phase 3.7: UDS + Trust-based authentication (no token required)
 * @param key データのキー
 * @param value データの値
 * @return 成功: true, 失敗: false
 */
bool send_to_db(const std::string& key, const std::string& value) {
    // 1. Unix Domain Socket作成
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "Failed to create UDS socket for DB: %s", strerror(errno));
        return false;
    }

    // 2. Data BrokerへUDS接続
    struct sockaddr_un db_addr;
    memset(&db_addr, 0, sizeof(db_addr));
    db_addr.sun_family = AF_UNIX;
    strncpy(db_addr.sun_path, DB_SOCKET_PATH, sizeof(db_addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&db_addr, sizeof(db_addr)) < 0) {
        syslog(LOG_ERR, "Failed to connect to DB via UDS: %s: %s",
               DB_SOCKET_PATH, strerror(errno));
        close(sock);
        return false;
    }

    // Phase 3.7: Trust-based authentication - no AUTH command needed
    // DB daemon automatically trusts UID=1000 (system) via SO_PEERCRED

    // 3. SETコマンド送信
    std::string command = "SET " + key + " " + value + "\n";
    ssize_t sent = send(sock, command.c_str(), command.length(), 0);
    if (sent < 0) {
        syslog(LOG_ERR, "Failed to send SET command: %s", strerror(errno));
        close(sock);
        return false;
    }

    // 4. レスポンス受信
    char response[256];
    memset(response, 0, sizeof(response));
    ssize_t received = recv(sock, response, sizeof(response) - 1, 0);

    if (received > 0) {
        response[received] = '\0';
        // 改行を除去
        if (response[received - 1] == '\n') {
            response[received - 1] = '\0';
        }
        syslog(LOG_INFO, "DB response: %s", response);
    }

    close(sock);
    return true;
}

/**
 * UDPマルチキャストソケットを作成
 * SO_REUSEADDR + IP_ADD_MEMBERSHIP を使用
 */
int create_multicast_socket() {
    // 1. ソケット作成
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        syslog(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    // 2. SO_REUSEADDR設定（重要！マルチキャスト受信の共有に必須）
    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        syslog(LOG_ERR, "Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(sock);
        return -1;
    }

    // 3. bind（INADDR_ANYで全インターフェースから受信）
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MULTICAST_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;  // 0.0.0.0

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
        close(sock);
        return -1;
    }

    // 4. マルチキャストグループに参加
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
    mreq.imr_interface.s_addr = INADDR_ANY;  // 全インターフェース

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        // Graceful degradation: エミュレータ等でmulticast不可の場合も継続
        syslog(LOG_WARNING, "Failed to join multicast group: %s (continuing without multicast)", strerror(errno));
        syslog(LOG_WARNING, "  This is expected on emulator - multicast receive disabled");
        // ソケットは閉じずに返す（UDS通信等は可能）
    } else {
        syslog(LOG_INFO, "Joined multicast group: %s", MULTICAST_GROUP);
    }

    syslog(LOG_INFO, "Multicast socket created");
    syslog(LOG_INFO, "  Group: %s", MULTICAST_GROUP);
    syslog(LOG_INFO, "  Port: %d", MULTICAST_PORT);
    syslog(LOG_INFO, "  SO_REUSEADDR: enabled");

    return sock;
}

/**
 * UDPパケットを受信してData Brokerへ転送
 */
void receive_loop(int sock) {
    char buffer[BUFFER_SIZE];
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    syslog(LOG_INFO, "Starting receive loop...");

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        memset(&sender_addr, 0, sizeof(sender_addr));

        // パケット受信
        ssize_t n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr*)&sender_addr, &addr_len);

        if (n < 0) {
            syslog(LOG_ERR, "recvfrom failed: %s", strerror(errno));
            continue;
        }

        // NULL終端
        buffer[n] = '\0';

        // 送信元情報
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, sizeof(sender_ip));
        int sender_port = ntohs(sender_addr.sin_port);

        // ログ出力
        syslog(LOG_INFO, "========================================");
        syslog(LOG_INFO, "Received UDP multicast packet");
        syslog(LOG_INFO, "  From: %s:%d", sender_ip, sender_port);
        syslog(LOG_INFO, "  Size: %zd bytes", n);
        syslog(LOG_INFO, "  Data: %s", buffer);

        // Data Brokerへ転送
        std::string data_str(buffer);

        // データをパース（簡易実装: "key=value" または "value" のみ）
        std::string key = "udp.data";
        std::string value = data_str;

        // "key=value" 形式の場合はパース
        size_t eq_pos = data_str.find('=');
        if (eq_pos != std::string::npos) {
            key = "udp." + data_str.substr(0, eq_pos);
            value = data_str.substr(eq_pos + 1);
        }

        syslog(LOG_INFO, "Forwarding to DB: %s = %s", key.c_str(), value.c_str());

        if (send_to_db(key, value)) {
            syslog(LOG_INFO, "Successfully forwarded to Data Broker");
        } else {
            syslog(LOG_ERR, "Failed to forward to Data Broker");
        }

        syslog(LOG_INFO, "========================================");
    }
}

int main() {
    // syslog初期化（POSIX標準）
    openlog("pal_daemon", LOG_PID | LOG_CONS, LOG_DAEMON);

    syslog(LOG_INFO, "PAL Daemon starting...");
    syslog(LOG_INFO, "Version: 3.7.0 (Phase 3.7 - UDS with Trust-based Authentication)");
    syslog(LOG_INFO, "Data Broker: %s (UDS)", DB_SOCKET_PATH);

    // マルチキャストソケット作成
    int sock = create_multicast_socket();
    if (sock < 0) {
        syslog(LOG_ERR, "Failed to initialize multicast socket");
        closelog();
        return 1;
    }

    // 受信ループ開始
    receive_loop(sock);

    // 通常ここには到達しない
    close(sock);
    closelog();
    return 0;
}
