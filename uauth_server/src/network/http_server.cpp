#include "http_server.h"
#include "http_session.h"
#include "settings/app_settings.h"

#include "spdlog/spdlog.h"

void http_server::on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket)
{
    if(ec!=boost::beast::errc::operation_canceled){
        if(logger_ptr_){
            logger_ptr_->debug("{}, accept incoming connection",
                               BOOST_CURRENT_FUNCTION);
        }

        const std::string& UA_DB {app_settings_ptr_->value_get("UA_DB")};
        const std::string& UA_DB_HOST {app_settings_ptr_->value_get("UA_DB_HOST")};
        const std::string& UA_DB_PORT {app_settings_ptr_->value_get("UA_DB_PORT")};
        const std::string& UA_DB_USER {app_settings_ptr_->value_get("UA_DB_USER")};
        const std::string& UA_DB_PASS {app_settings_ptr_->value_get("UA_DB_PASS")};

        if(UA_DB.empty() || UA_DB_HOST.empty() || UA_DB_PORT.empty() || UA_DB_USER.empty() || UA_DB_PASS.empty()){
            if(logger_ptr_){
               logger_ptr_->critical("{}, db params not defined in app_settings!",
                   BOOST_CURRENT_FUNCTION);
           }
        }
        else{
            const boost::json::object& params {
                {"UA_DB",UA_DB},
                {"UA_DB_HOST",UA_DB_HOST},
                {"UA_DB_PORT",UA_DB_PORT},
                {"UA_DB_USER",UA_DB_USER},
                {"UA_DB_PASS",UA_DB_PASS}
            };
            std::make_shared<http_session>(std::move(socket),params,logger_ptr_)->session_run();
        }
        acceptor_.async_accept(boost::asio::make_strand(io_),
            boost::beast::bind_front_handler(&http_server::on_accept,shared_from_this()));
    }
}

http_server::http_server(boost::asio::io_context &io, const std::string &app_dir, std::shared_ptr<app_settings> app_settings_ptr, std::shared_ptr<spdlog::logger> logger_ptr)
    :io_{io},acceptor_{io_},app_dir_{app_dir},app_settings_ptr_{app_settings_ptr},logger_ptr_{logger_ptr}
{
}

bool http_server::server_listen()
{
    const std::string& UA_HOST {app_settings_ptr_->value_get("UA_HOST")};
    const std::string& UA_PORT {app_settings_ptr_->value_get("UA_PORT")};

    if(UA_HOST.empty() || UA_PORT.empty()){
        if(logger_ptr_){
            logger_ptr_->critical("{}, 'UA_HOST' and 'UA_PORT' not defined in app_settings!",
                BOOST_CURRENT_FUNCTION);
        }
        return false;
    };
    const unsigned short& UA_PORT_ {static_cast<unsigned short>(std::stoi(UA_PORT))};

    boost::beast::error_code ec;
    boost::asio::ip::tcp::endpoint ep {boost::asio::ip::address::from_string(UA_HOST),UA_PORT_};

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
        boost::beast::bind_front_handler(&http_server::on_accept,shared_from_this()));
    return true;
}

void http_server::server_stop()
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
