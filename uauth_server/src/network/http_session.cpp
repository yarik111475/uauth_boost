#include "http_session.h"
#include <chrono>
#include <boost/url.hpp>

#include "spdlog/spdlog.h"

void http_session::do_read()
{
    request_={};
    stream_.expires_after(std::chrono::seconds(60));
    boost::beast::http::async_read(stream_,buffer_,request_,
        boost::beast::bind_front_handler(&http_session::on_read,shared_from_this()));
}

void http_session::do_close()
{
    boost::beast::error_code ec;
    stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send,ec);
}

void http_session::on_read(boost::beast::error_code ec, size_t bytes_transferred)
{
    if(ec==boost::beast::http::error::end_of_stream || ec){
        if(logger_ptr_){
            logger_ptr_->error("{}, close session with error: {}",
                BOOST_CURRENT_FUNCTION,ec.message());
        }
        return do_close();
    }
    http::message_generator response=
        handle_request(std::move(request_));
    boost::beast::async_write(stream_,std::move(response),
        boost::beast::bind_front_handler(&http_session::on_write,shared_from_this()));
}

void http_session::on_write(error_code ec, size_t bytes_transferred)
{
    if(ec){
        if(logger_ptr_){
            logger_ptr_->error("{},{}",
                BOOST_CURRENT_FUNCTION,ec.message());
        }
        return;
    }
    return do_close();
}

http_session::http_session(boost::asio::ip::tcp::socket &&socket, const boost::json::object &params, std::shared_ptr<spdlog::logger> logger_ptr)
    :stream_{std::move(socket)},params_{params},logger_ptr_{logger_ptr}
{
    http_handler_ptr_.reset(new http_handler{params_,logger_ptr});
}

void http_session::session_run()
{
    boost::asio::dispatch(stream_.get_executor(),
        boost::beast::bind_front_handler(&http_session::do_read,shared_from_this()));
}

