#ifndef UC_CONTROLLER_H
#define UC_CONTROLLER_H

#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include "defines.h"

namespace spdlog{
    class logger;
}

class uc_controller
{
private:
    boost::asio::io_context& io_;
    boost::asio::deadline_timer timer_;
    boost::json::object params_ {};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};
    void on_wait(boost::system::error_code& ec);

public:
    explicit uc_controller(boost::asio::io_context& io,const boost::json::object& params,std::shared_ptr<spdlog::logger> logger_ptr);
    ~uc_controller();
    void controller_start();
    void controller_stop();
};

#endif // UC_CONTROLLER_H
