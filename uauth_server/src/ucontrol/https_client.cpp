#include "https_client.h"
#include <iostream>

boost::optional<boost::asio::ssl::context> https_client::make_context()
{
    const std::string& x509_root_path {params_.at("x509_root_path").as_string().c_str()};
    const std::string& x509_client_path {params_.at("x509_client_path").as_string().c_str()};
    const std::string& PKEY_client_path {params_.at("PKEY_client_path").as_string().c_str()};
    const std::string& PKEY_client_pass {params_.at("PKEY_client_pass").as_string().c_str()};
    boost::ignore_unused(PKEY_client_pass);

    boost::system::error_code ec;
    boost::asio::ssl::context ctx {boost::asio::ssl::context_base::sslv23_client};
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    ctx.use_certificate_chain_file(x509_root_path,ec);
    ctx.use_certificate_file(x509_client_path,boost::asio::ssl::context::pem,ec);
    ctx.use_private_key_file(PKEY_client_path,boost::asio::ssl::context::pem,ec);
    if(ec){
        return boost::none;
    }
    return ctx;
}

https_client::https_client(boost::asio::io_context &io,const std::string& app_dir,const boost::json::object &params)
    :io_{io},app_dir_{app_dir},params_{params}
{
}

void https_client::client_run()
{
    boost::optional<boost::asio::ssl::context> ctx {make_context()};
    if(!ctx){
        return;
    }

    const std::string& host {params_.at("host").as_string().c_str()};
    const unsigned short& port {static_cast<unsigned short>(params_.at("port").as_int64())};

    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver resolvser {io_};
    const auto& results {resolvser.resolve(host,std::to_string(port),ec)};
    if(ec){
        return;
    }

    boost::beast::ssl_stream<boost::asio::ip::tcp::socket> socket {io_,ctx.value()};
    boost::beast::get_lowest_layer(socket).connect(*results.begin(),ec);
    if(ec){
        return;
    }
    socket.set_verify_callback([&](bool preverified,boost::asio::ssl::verify_context& ctx){
        return true;
    });
    socket.handshake(boost::asio::ssl::stream_base::client,ec);
    if(ec){
        std::cout<<ec.message()<<std::endl;
        return;
    }
    if(! SSL_set_tlsext_host_name(socket.native_handle(), host.c_str())){
        return;
    }
    socket.set_verify_callback([&](bool preverified,boost::asio::ssl::verify_context& ctx){
        return true;
    });

    boost::beast::http::request<boost::beast::http::string_body> request{boost::beast::http::verb::get, "/integrity", 11};
    request.set(boost::beast::http::field::host, host);
    request.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    boost::beast::http::write(socket,request,ec);
    if(ec){
        return;
    }

    boost::beast::flat_buffer buffer;
    boost::beast::http::response<boost::beast::http::string_body> response;
    boost::beast::http::read(socket, buffer, response,ec);
    std::cout<<response.body()<<std::endl;
    socket.shutdown(ec);
}

