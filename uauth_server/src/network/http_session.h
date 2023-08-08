#ifndef HTTP_SESSION_H
#define HTTP_SESSION_H

#include <string>
#include <memory>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http/message_generator.hpp>

#include "http_handler.h"

namespace spdlog{
    class logger;
}
using namespace boost::beast;

class http_session:public std::enable_shared_from_this<http_session>
{
private:
    boost::beast::tcp_stream stream_;
    boost::json::object params_ {};
    boost::beast::flat_buffer buffer_;
    std::shared_ptr<std::string> reponse_body_ {nullptr};
    http::request<http::string_body> request_;

    std::shared_ptr<http_handler> http_handler_ptr_ {nullptr};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};

    void do_read();
    void do_close();
    void on_read(boost::beast::error_code ec,std::size_t bytes_transferred);
    void on_write(boost::beast::error_code ec,std::size_t bytes_transferred);

    template <class Body, class Allocator>
    http::message_generator handle_request(http::request<Body, http::basic_fields<Allocator>>&& request){
        return http_handler_ptr_->handle_request(std::move(request));
    }

public:
    explicit http_session(boost::asio::ip::tcp::socket&& socket,const boost::json::object& params,uc_status status,std::shared_ptr<spdlog::logger> logger_ptr);
    void session_run();
};

#endif // HTTP_SESSION_H
