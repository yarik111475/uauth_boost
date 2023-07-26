#include "http_uauth_server.h"
#include "http_uauth_session.h"
#include "settings/app_settings.h"

#include "spdlog/spdlog.h"

void http_uauth_server::on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
{
    if(ec!=boost::beast::errc::operation_canceled){
        if(logger_ptr_){
            logger_ptr_->debug("{}, accept incoming connection",
                               BOOST_CURRENT_FUNCTION);
        }

        std::string db_user {};
        std::string db_pass {};
        std::string db_host {};
        std::string db_port {};
        std::string db_name {};

        if(!app_settings_ptr_->value_get("db_user",db_user) || !app_settings_ptr_->value_get("db_pass",db_pass) ||
           !app_settings_ptr_->value_get("db_host",db_host) || !app_settings_ptr_->value_get("db_port",db_port) || !app_settings_ptr_->value_get("db_name",db_name)){
           if(logger_ptr_){
               logger_ptr_->critical("{}, db params not defined in app_settings!",
                   BOOST_CURRENT_FUNCTION);
           }
        }
        else{
            const boost::json::object& params {
                {"db_user",db_user},
                {"db_pass",db_pass},
                {"db_host",db_host},
                {"db_port",db_port},
                {"db_name",db_name}
            };
            std::make_shared<http_uauth_session>(std::move(socket),params,logger_ptr_)->session_run();
        }
        acceptor_.async_accept(boost::asio::make_strand(io_),
            boost::beast::bind_front_handler(&http_uauth_server::on_accept,shared_from_this()));
    }
}

http_uauth_server::http_uauth_server(boost::asio::io_context &io, const std::string &app_dir, std::shared_ptr<app_settings> app_settings_ptr, std::shared_ptr<spdlog::logger> logger_ptr)
    :io_{io},acceptor_{io_},app_dir_{app_dir},app_settings_ptr_{app_settings_ptr},logger_ptr_{logger_ptr}
{
}

bool http_uauth_server::server_listen()
{
    std::string host;
    std::string port;
    if(!app_settings_ptr_->value_get("host",host) || !app_settings_ptr_->value_get("port",port)){
        if(logger_ptr_){
            logger_ptr_->critical("{}, 'host' and 'port' not defined in app_settings!",
                BOOST_CURRENT_FUNCTION);
        }
        return false;
    }
    const unsigned short& port_ {static_cast<unsigned short>(std::stoi(port))};

    boost::beast::error_code ec;
    boost::asio::ip::tcp::endpoint ep {boost::asio::ip::address::from_string(host),port_};

    acceptor_.open(ep.protocol(),ec);
    if(ec){
        if(logger_ptr_){
            logger_ptr_->critical("{}, error message: {}",
                BOOST_CURRENT_FUNCTION,ec.message());
        }
        return false;
    }

    acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if(ec)
    {
        if(logger_ptr_){
            logger_ptr_->critical("{}, error message: {}",
                BOOST_CURRENT_FUNCTION,ec.message());
        }
        return false;
    }

    //bind to the server address
    acceptor_.bind(ep, ec);
    if(ec){
        if(logger_ptr_){
            logger_ptr_->critical("{}, error message: {}",
                BOOST_CURRENT_FUNCTION,ec.message());
        }
        return false;
    }

    //start listening for connections
    acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if(ec){
        if(logger_ptr_){
            logger_ptr_->critical("{}, error message: {}",
                BOOST_CURRENT_FUNCTION,ec.message());
        }
        return false;
    }
    if(logger_ptr_){
        logger_ptr_->info("{}, http_uauth_server begin accept",
            BOOST_CURRENT_FUNCTION);
    }

    acceptor_.async_accept(boost::asio::make_strand(io_),
        boost::beast::bind_front_handler(&http_uauth_server::on_accept,shared_from_this()));
    return true;
}

void http_uauth_server::server_stop()
{
    boost::system::error_code ec;
    if(acceptor_.is_open()){
        acceptor_.cancel(ec);
        acceptor_.close(ec);
    }
    if(logger_ptr_){
        logger_ptr_->info("{}, http_server stopped",
            BOOST_CURRENT_FUNCTION);
    }
}
