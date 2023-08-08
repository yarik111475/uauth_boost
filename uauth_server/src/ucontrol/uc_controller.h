#ifndef UC_CONTROLLER_H
#define UC_CONTROLLER_H

#include <string>
#include <memory>
#include <functional>
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include "defines.h"

namespace spdlog{
    class logger;
}
class https_client;

class uc_controller
{
private:
    const int interval_ {2000};
    boost::asio::io_context& io_;
    boost::asio::deadline_timer timer_;
    boost::json::object params_ {};
    std::shared_ptr<https_client> https_client_ptr_ {nullptr};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};
    void on_wait(const boost::system::error_code& ec);
    void uc_status_slot(uc_status status,const std::string& msg);

public:
    explicit uc_controller(boost::asio::io_context& io,const boost::json::object& params,std::shared_ptr<spdlog::logger> logger_ptr);
    ~uc_controller()=default;
    void controller_start();
    void controller_stop();
    std::function<void(uc_status status,const std::string& msg)> uc_status_signal_ {nullptr};
};

#endif // UC_CONTROLLER_H
