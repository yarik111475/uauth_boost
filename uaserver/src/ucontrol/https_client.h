#ifndef HTTPS_CLIENT_H
#define HTTPS_CLIENT_H

#include <string>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/optional.hpp>
#include "defines.h"

namespace spdlog{
    class logger;
}

class https_client
{
    boost::asio::io_context& io_;
    std::string app_dir_ {};
    boost::json::object params_ {};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};
    boost::optional<boost::asio::ssl::context> make_context();

public:
    explicit https_client(boost::asio::io_context& io,
        const std::string& app_dir,const boost::json::object& params,std::shared_ptr<spdlog::logger> logger_ptr);
    ~https_client();
    void client_run();
    std::function<void(uc_status status,const std::string& msg)> uc_status_signal_ {nullptr};
};

#endif // HTTPS_CLIENT_H
