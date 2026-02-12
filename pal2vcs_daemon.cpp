/**
 * PAL2VCS Daemon (Phase 4.2)
 *
 * SET direction: Data Broker -> PAL2VCS -> VCS (via SOME/IP)
 *
 * This daemon:
 * 1. Listens on UDS for control requests from Data Broker
 * 2. Sends SOME/IP requests to VCS
 * 3. Returns responses back to Data Broker
 *
 * UDS Protocol:
 *   Request:  "CONTROL key=value\n"
 *   Response: "OK\n" or "ERROR:reason\n"
 */

#include <vsomeip/vsomeip.hpp>

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
constexpr vsomeip::method_t VCS_METHOD_ID = 0x0421;

// UDS configuration (Phase 4.2.1: use /data/misc/ for SELinux compatibility)
constexpr const char* PAL2VCS_SOCKET_PATH = "/data/misc/vsomeip/pal2vcs.sock";
constexpr int BUFFER_SIZE = 1024;
constexpr int RESPONSE_TIMEOUT_MS = 5000;

class Pal2VcsDaemon {
public:
    Pal2VcsDaemon() :
        app_(vsomeip::runtime::get()->create_application("pal2vcs_daemon")),
        running_(true),
        service_available_(false),
        waiting_for_response_(false) {
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

        // Register message handler for responses
        app_->register_message_handler(
            VCS_SERVICE_ID, VCS_INSTANCE_ID, VCS_METHOD_ID,
            std::bind(&Pal2VcsDaemon::on_response, this, std::placeholders::_1));

        // Request the VCS service
        app_->request_service(VCS_SERVICE_ID, VCS_INSTANCE_ID);

        syslog(LOG_INFO, "vsomeip initialized, requesting service 0x%04x.0x%04x",
               VCS_SERVICE_ID, VCS_INSTANCE_ID);

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

        std::lock_guard<std::mutex> lock(mutex_);
        service_available_ = available;
        cv_.notify_all();
    }

    // vsomeip response handler
    void on_response(const std::shared_ptr<vsomeip::message>& response) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!waiting_for_response_) {
            syslog(LOG_WARNING, "Received unexpected response");
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

        syslog(LOG_INFO, "Received response: %s", last_response_.c_str());

        waiting_for_response_ = false;
        cv_.notify_all();
    }

    // Send control command to VCS via SOME/IP
    std::string send_to_vcs(const std::string& command) {
        std::unique_lock<std::mutex> lock(mutex_);

        // Check service availability
        if (!service_available_) {
            syslog(LOG_ERR, "VCS service not available");
            return "ERROR:SERVICE_UNAVAILABLE";
        }

        // Create request
        auto request = vsomeip::runtime::get()->create_request();
        request->set_service(VCS_SERVICE_ID);
        request->set_instance(VCS_INSTANCE_ID);
        request->set_method(VCS_METHOD_ID);

        // Set payload
        auto payload = vsomeip::runtime::get()->create_payload();
        std::vector<vsomeip::byte_t> data(command.begin(), command.end());
        payload->set_data(data);
        request->set_payload(payload);

        // Setup response waiting
        waiting_for_response_ = true;
        last_response_.clear();

        // Send request
        syslog(LOG_INFO, "Sending SOME/IP request: %s", command.c_str());
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
};

int main() {
    // Initialize syslog
    openlog("pal2vcs_daemon", LOG_PID | LOG_CONS, LOG_DAEMON);

    syslog(LOG_INFO, "========================================");
    syslog(LOG_INFO, "PAL2VCS Daemon starting (Phase 4.2)");
    syslog(LOG_INFO, "========================================");
    syslog(LOG_INFO, "UDS socket: %s", PAL2VCS_SOCKET_PATH);
    syslog(LOG_INFO, "VCS Service: 0x%04x.0x%04x, Method: 0x%04x",
           VCS_SERVICE_ID, VCS_INSTANCE_ID, VCS_METHOD_ID);

    Pal2VcsDaemon daemon;

    if (!daemon.init()) {
        syslog(LOG_ERR, "Failed to initialize daemon");
        closelog();
        return 1;
    }

    syslog(LOG_INFO, "Initialization complete, starting daemon...");

    daemon.start();

    closelog();
    return 0;
}
