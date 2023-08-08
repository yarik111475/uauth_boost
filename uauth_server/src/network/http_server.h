#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H
#include "defines.h"

#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <boost/beast.hpp>

namespace spdlog{
    class logger;
}
class app_settings;

class http_server:public std::enable_shared_from_this<http_server>
{
private:
    uc_status status_ {uc_status::fail};
    boost::asio::io_context& io_;
    boost::asio::ip::tcp::acceptor acceptor_;

    std::string app_dir_ {};
    boost::json::object params_ {};
    std::shared_ptr<app_settings> app_settings_ptr_ {nullptr};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};

    void on_accept(boost::beast::error_code ec,boost::asio::ip::tcp::socket socket);

public:
    explicit http_server(boost::asio::io_context& io,const std::string& app_dir,std::shared_ptr<app_settings> app_settings_ptr,std::shared_ptr<spdlog::logger> logger_ptr);
    bool server_listen();
    void server_stop();
    void uc_status_slot(uc_status status,const std::string& msg);
};

#endif // HTTP_SERVER_H
