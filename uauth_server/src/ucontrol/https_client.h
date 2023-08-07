#ifndef HTTPS_CLIENT_H
#define HTTPS_CLIENT_H

#include <string>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/optional.hpp>

class https_client
{
boost::asio::io_context& io_;
    std::string app_dir_ {};
    boost::json::object params_ {};

    void init_spdlog();
    boost::optional<boost::asio::ssl::context> make_context();
public:
    explicit https_client(boost::asio::io_context& io,const std::string& app_dir,const boost::json::object& params);
    ~https_client()=default;
    void client_run();
};

#endif // HTTPS_CLIENT_H
