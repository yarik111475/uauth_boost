#ifndef HTTP_SESSION_H
#define HTTP_SESSION_H

#include <string>
#include <memory>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include "http_handler.h"

namespace spdlog{
    class logger;
}

class http_session:public std::enable_shared_from_this<http_session>
{
private:
    boost::beast::tcp_stream stream_;
    boost::json::object params_ {};
    boost::beast::flat_buffer buffer_;
    std::shared_ptr<std::string> reponse_body_ {nullptr};
    boost::beast::http::request<boost::beast::http::string_body> request_;

    std::shared_ptr<http_handler> http_handler_ptr_ {nullptr};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};

    void do_read();
    void do_close();
    void on_read(boost::beast::error_code ec,std::size_t bytes_transferred);
    void on_write(bool keep_alive,boost::beast::error_code ec,std::size_t bytes_transferred);
    response_t handle_request(request_t&& request);

public:
    explicit http_session(boost::asio::ip::tcp::socket&& socket,const boost::json::object& params,std::shared_ptr<spdlog::logger> logger_ptr);
    void session_run();
};

#endif // HTTP_SESSION_H
