/**
 * PAL2VCS Daemon (Phase 4.3)
 *
 * SET direction: Data Broker -> PAL2VCS -> VCS (via SOME/IP)
 *
 * This daemon:
 * 1. Listens on UDS for control requests from Data Broker
 * 2. Performs ECDH key exchange with VCS (via KeystoreCrypto service)
 * 3. Sends MAC-authenticated SOME/IP requests to VCS
 * 4. Returns responses back to Data Broker
 *
 * UDS Protocol:
 *   Request:  "CONTROL key=value\n"
 *   Response: "OK\n" or "ERROR:reason\n"
 *
 * SOME/IP Protocol (Phase 4.3):
 *   KEY_EXCHANGE (0x0422): pubkey_hex (130 chars) -> vcs_pubkey_hex
 *   CONTROL (0x0421): "command:MAC_HEX" -> "OK" or "ERROR:reason"
 */

#include <vsomeip/vsomeip.hpp>
#include "keystore_crypto_client.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

// SOME/IP IDs (must match VCS mock / sample_ids.hpp)
constexpr vsomeip::service_t VCS_SERVICE_ID = 0x1234;
constexpr vsomeip::instance_t VCS_INSTANCE_ID = 0x5678;
constexpr vsomeip::method_t VCS_METHOD_CONTROL = 0x0421;
constexpr vsomeip::method_t VCS_METHOD_KEY_EXCHANGE = 0x0422;

// UDS configuration (Phase 4.2.1: use /data/misc/ for SELinux compatibility)
constexpr const char* PAL2VCS_SOCKET_PATH = "/data/misc/vsomeip/pal2vcs.sock";
constexpr int BUFFER_SIZE = 1024;
constexpr int RESPONSE_TIMEOUT_MS = 5000;

// Phase 4.3: Crypto state
enum class CryptoState {
    NOT_STARTED,        // Key exchange not yet initiated
    KEY_EXCHANGE_SENT,  // KEY_EXCHANGE request sent, waiting for response
    READY               // Shared key established, MAC enabled
};

class Pal2VcsDaemon {
public:
    Pal2VcsDaemon() :
        app_(vsomeip::runtime::get()->create_application("pal2vcs_daemon")),
        running_(true),
        service_available_(false),
        waiting_for_response_(false),
        crypto_state_(CryptoState::NOT_STARTED) {
    }

    ~Pal2VcsDaemon() {
        stop();
    }

    bool init() {
        // Initialize vsomeip
        if (!app_->init()) {
            syslog(LOG_ERR, "Failed to initialize vsomeip application");
            return false;
        }

        // Register state handler
        app_->register_state_handler(
            std::bind(&Pal2VcsDaemon::on_state, this, std::placeholders::_1));

        // Register availability handler
        app_->register_availability_handler(
            VCS_SERVICE_ID, VCS_INSTANCE_ID,
            std::bind(&Pal2VcsDaemon::on_availability, this,
                      std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));

        // Register message handler for CONTROL responses
        app_->register_message_handler(
            VCS_SERVICE_ID, VCS_INSTANCE_ID, VCS_METHOD_CONTROL,
            std::bind(&Pal2VcsDaemon::on_control_response, this, std::placeholders::_1));

        // Phase 4.3: Register message handler for KEY_EXCHANGE responses
        app_->register_message_handler(
            VCS_SERVICE_ID, VCS_INSTANCE_ID, VCS_METHOD_KEY_EXCHANGE,
            std::bind(&Pal2VcsDaemon::on_key_exchange_response, this, std::placeholders::_1));

        // Request the VCS service
        app_->request_service(VCS_SERVICE_ID, VCS_INSTANCE_ID);

        syslog(LOG_INFO, "vsomeip initialized, requesting service 0x%04x.0x%04x",
               VCS_SERVICE_ID, VCS_INSTANCE_ID);
        syslog(LOG_INFO, "Methods: CONTROL=0x%04x, KEY_EXCHANGE=0x%04x",
               VCS_METHOD_CONTROL, VCS_METHOD_KEY_EXCHANGE);

        return true;
    }

    void start() {
        // Start vsomeip in a separate thread
        vsomeip_thread_ = std::thread([this]() {
            app_->start();
        });

        // Start UDS server
        uds_server_loop();
    }

    void stop() {
        running_ = false;

        // Stop vsomeip
        if (app_) {
            app_->stop();
        }

        if (vsomeip_thread_.joinable()) {
            vsomeip_thread_.join();
        }
    }

private:
    // vsomeip state handler
    void on_state(vsomeip::state_type_e state) {
        if (state == vsomeip::state_type_e::ST_REGISTERED) {
            syslog(LOG_INFO, "vsomeip application registered");
        }
    }

    // vsomeip availability handler
    void on_availability(vsomeip::service_t service,
                        vsomeip::instance_t instance,
                        bool available) {
        syslog(LOG_INFO, "Service [0x%04x.0x%04x] is %s",
               service, instance, available ? "available" : "not available");

        {
            std::lock_guard<std::mutex> lock(mutex_);
            service_available_ = available;
            cv_.notify_all();
        }

        // Phase 4.3: Initiate key exchange when service becomes available
        if (available && crypto_state_ == CryptoState::NOT_STARTED) {
            initiate_key_exchange();
        }
    }

    // Phase 4.3: Initiate ECDH key exchange
    void initiate_key_exchange() {
        syslog(LOG_INFO, "[Phase 4.3] Initiating key exchange...");

        // Generate our ECDH key pair via KeystoreCrypto service
        auto our_pubkey = crypto_client_.generateKey();
        if (our_pubkey.empty()) {
            syslog(LOG_ERR, "[Phase 4.3] Failed to generate key pair");
            return;
        }

        syslog(LOG_INFO, "[Phase 4.3] Generated ECDH key pair, sending KEY_EXCHANGE request");

        // Send KEY_EXCHANGE request with our public key
        auto request = vsomeip::runtime::get()->create_request();
        request->set_service(VCS_SERVICE_ID);
        request->set_instance(VCS_INSTANCE_ID);
        request->set_method(VCS_METHOD_KEY_EXCHANGE);

        // Payload: public key as hex string (130 chars)
        std::string pubkey_hex = keystore_crypto::bytesToHex(our_pubkey);
        auto payload = vsomeip::runtime::get()->create_payload();
        std::vector<vsomeip::byte_t> data(pubkey_hex.begin(), pubkey_hex.end());
        payload->set_data(data);
        request->set_payload(payload);

        crypto_state_ = CryptoState::KEY_EXCHANGE_SENT;
        app_->send(request);

        syslog(LOG_INFO, "[Phase 4.3] KEY_EXCHANGE request sent (pubkey: %s...)",
               pubkey_hex.substr(0, 16).c_str());
    }

    // Phase 4.3: Handle KEY_EXCHANGE response
    void on_key_exchange_response(const std::shared_ptr<vsomeip::message>& response) {
        syslog(LOG_INFO, "[Phase 4.3] Received KEY_EXCHANGE response");

        if (crypto_state_ != CryptoState::KEY_EXCHANGE_SENT) {
            syslog(LOG_WARNING, "[Phase 4.3] Unexpected KEY_EXCHANGE response (state=%d)",
                   static_cast<int>(crypto_state_));
            return;
        }

        // Extract VCS public key from response
        auto payload = response->get_payload();
        if (!payload || payload->get_length() == 0) {
            syslog(LOG_ERR, "[Phase 4.3] Empty KEY_EXCHANGE response");
            crypto_state_ = CryptoState::NOT_STARTED;
            return;
        }

        std::string vcs_pubkey_hex(
            reinterpret_cast<const char*>(payload->get_data()),
            payload->get_length()
        );

        // Check for error response
        if (vcs_pubkey_hex.substr(0, 5) == "ERROR") {
            syslog(LOG_ERR, "[Phase 4.3] KEY_EXCHANGE failed: %s", vcs_pubkey_hex.c_str());
            crypto_state_ = CryptoState::NOT_STARTED;
            return;
        }

        syslog(LOG_INFO, "[Phase 4.3] VCS public key: %s...",
               vcs_pubkey_hex.substr(0, 16).c_str());

        // Derive shared key
        auto vcs_pubkey = keystore_crypto::hexToBytes(vcs_pubkey_hex);
        if (!crypto_client_.deriveKey(vcs_pubkey)) {
            syslog(LOG_ERR, "[Phase 4.3] Failed to derive shared key");
            crypto_state_ = CryptoState::NOT_STARTED;
            return;
        }

        crypto_state_ = CryptoState::READY;
        syslog(LOG_INFO, "[Phase 4.3] ✅ Key exchange completed, MAC enabled");
    }

    // vsomeip CONTROL response handler
    void on_control_response(const std::shared_ptr<vsomeip::message>& response) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!waiting_for_response_) {
            syslog(LOG_WARNING, "Received unexpected CONTROL response");
            return;
        }

        // Extract response payload
        auto payload = response->get_payload();
        if (payload && payload->get_length() > 0) {
            last_response_ = std::string(
                reinterpret_cast<const char*>(payload->get_data()),
                payload->get_length()
            );
        } else {
            last_response_ = "OK";
        }

        syslog(LOG_INFO, "Received CONTROL response: %s", last_response_.c_str());

        waiting_for_response_ = false;
        cv_.notify_all();
    }

    // Send control command to VCS via SOME/IP (Phase 4.3: with MAC)
    std::string send_to_vcs(const std::string& command) {
        std::unique_lock<std::mutex> lock(mutex_);

        // Check service availability
        if (!service_available_) {
            syslog(LOG_ERR, "VCS service not available");
            return "ERROR:SERVICE_UNAVAILABLE";
        }

        // Phase 4.3: Build payload with MAC if key exchange completed
        std::string payload_str;
        if (crypto_state_ == CryptoState::READY) {
            // Compute MAC for the command
            std::vector<uint8_t> cmd_bytes(command.begin(), command.end());
            auto mac = crypto_client_.computeMac(cmd_bytes);
            if (mac.empty()) {
                syslog(LOG_ERR, "[Phase 4.3] Failed to compute MAC");
                return "ERROR:MAC_FAILED";
            }

            // Format: "command:MAC_HEX"
            payload_str = command + ":" + keystore_crypto::bytesToHex(mac);
            syslog(LOG_INFO, "[Phase 4.3] CONTROL with MAC: %s:%s...",
                   command.c_str(), keystore_crypto::bytesToHex(mac).substr(0, 16).c_str());
        } else {
            // No MAC (key exchange not completed or legacy mode)
            payload_str = command;
            syslog(LOG_INFO, "CONTROL without MAC: %s", command.c_str());
        }

        // Create request
        auto request = vsomeip::runtime::get()->create_request();
        request->set_service(VCS_SERVICE_ID);
        request->set_instance(VCS_INSTANCE_ID);
        request->set_method(VCS_METHOD_CONTROL);

        // Set payload
        auto payload = vsomeip::runtime::get()->create_payload();
        std::vector<vsomeip::byte_t> data(payload_str.begin(), payload_str.end());
        payload->set_data(data);
        request->set_payload(payload);

        // Setup response waiting
        waiting_for_response_ = true;
        last_response_.clear();

        // Send request
        app_->send(request);

        // Wait for response with timeout
        auto status = cv_.wait_for(lock, std::chrono::milliseconds(RESPONSE_TIMEOUT_MS),
                                   [this]() { return !waiting_for_response_; });

        if (!status) {
            syslog(LOG_ERR, "Timeout waiting for VCS response");
            waiting_for_response_ = false;
            return "ERROR:TIMEOUT";
        }

        return last_response_;
    }

    // UDS server loop
    void uds_server_loop() {
        // Create UDS socket
        int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd < 0) {
            syslog(LOG_ERR, "Failed to create UDS socket: %s", strerror(errno));
            return;
        }

        // Remove existing socket file
        unlink(PAL2VCS_SOCKET_PATH);

        // Bind
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, PAL2VCS_SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            syslog(LOG_ERR, "Failed to bind UDS socket: %s", strerror(errno));
            close(server_fd);
            return;
        }

        // Set permissions (allow other processes to connect)
        chmod(PAL2VCS_SOCKET_PATH, 0666);

        // Listen
        if (listen(server_fd, 5) < 0) {
            syslog(LOG_ERR, "Failed to listen on UDS socket: %s", strerror(errno));
            close(server_fd);
            return;
        }

        syslog(LOG_INFO, "UDS server listening on %s", PAL2VCS_SOCKET_PATH);

        while (running_) {
            // Accept connection
            int client_fd = accept(server_fd, nullptr, nullptr);
            if (client_fd < 0) {
                if (running_) {
                    syslog(LOG_ERR, "Failed to accept connection: %s", strerror(errno));
                }
                continue;
            }

            // Handle client in current thread (simple sequential handling)
            handle_client(client_fd);
            close(client_fd);
        }

        close(server_fd);
        unlink(PAL2VCS_SOCKET_PATH);
    }

    // Handle UDS client request
    void handle_client(int client_fd) {
        char buffer[BUFFER_SIZE];
        memset(buffer, 0, sizeof(buffer));

        // Read request
        ssize_t n = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) {
            return;
        }

        std::string request(buffer);

        // Remove trailing newline
        while (!request.empty() && (request.back() == '\n' || request.back() == '\r')) {
            request.pop_back();
        }

        syslog(LOG_INFO, "UDS request: %s", request.c_str());

        std::string response;

        // Parse command
        if (request.substr(0, 8) == "CONTROL ") {
            std::string command = request.substr(8);
            response = send_to_vcs(command);
        } else if (request == "STATUS") {
            response = service_available_ ? "SERVICE_AVAILABLE" : "SERVICE_UNAVAILABLE";
        } else if (request == "CRYPTO_STATUS") {
            // Phase 4.3: Report crypto state
            switch (crypto_state_) {
                case CryptoState::NOT_STARTED:
                    response = "CRYPTO:NOT_STARTED";
                    break;
                case CryptoState::KEY_EXCHANGE_SENT:
                    response = "CRYPTO:KEY_EXCHANGE_SENT";
                    break;
                case CryptoState::READY:
                    response = "CRYPTO:READY";
                    break;
            }
        } else if (request == "KEY_EXCHANGE") {
            // Phase 4.3: Manual key exchange trigger
            if (crypto_state_ == CryptoState::READY) {
                response = "CRYPTO:ALREADY_READY";
            } else if (service_available_) {
                initiate_key_exchange();
                response = "CRYPTO:KEY_EXCHANGE_INITIATED";
            } else {
                response = "ERROR:SERVICE_UNAVAILABLE";
            }
        } else {
            response = "ERROR:UNKNOWN_COMMAND";
        }

        // Send response
        response += "\n";
        send(client_fd, response.c_str(), response.length(), 0);

        syslog(LOG_INFO, "UDS response: %s", response.c_str());
    }

    std::shared_ptr<vsomeip::application> app_;
    std::thread vsomeip_thread_;

    std::atomic<bool> running_;
    std::atomic<bool> service_available_;

    std::mutex mutex_;
    std::condition_variable cv_;

    bool waiting_for_response_;
    std::string last_response_;

    // Phase 4.3: Crypto state and client
    CryptoState crypto_state_;
    mutable keystore_crypto::KeystoreCryptoClient crypto_client_;
};

int main() {
    // Initialize syslog
    openlog("pal2vcs_daemon", LOG_PID | LOG_CONS, LOG_DAEMON);

    syslog(LOG_INFO, "========================================");
    syslog(LOG_INFO, "PAL2VCS Daemon starting (Phase 4.3)");
    syslog(LOG_INFO, "  MAC Authentication + SOME/IP");
    syslog(LOG_INFO, "========================================");
    syslog(LOG_INFO, "UDS socket: %s", PAL2VCS_SOCKET_PATH);
    syslog(LOG_INFO, "VCS Service: 0x%04x.0x%04x", VCS_SERVICE_ID, VCS_INSTANCE_ID);
    syslog(LOG_INFO, "  CONTROL: 0x%04x, KEY_EXCHANGE: 0x%04x",
           VCS_METHOD_CONTROL, VCS_METHOD_KEY_EXCHANGE);

    Pal2VcsDaemon daemon;

    if (!daemon.init()) {
        syslog(LOG_ERR, "Failed to initialize daemon");
        closelog();
        return 1;
    }

    syslog(LOG_INFO, "Initialization complete, starting daemon...");
    syslog(LOG_INFO, "Key exchange will be initiated when VCS service becomes available");

    daemon.start();

    closelog();
    return 0;
}
