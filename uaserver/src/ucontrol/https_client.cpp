#include "https_client.h"

#include "spdlog/spdlog.h"

boost::optional<boost::asio::ssl::context> https_client::make_context()
{
    if(!params_.contains("UA_CA_CRT_PATH") || !params_.contains("UA_CLIENT_CRT_PATH") || !params_.contains("UA_CLIENT_KEY_PATH")){
        return boost::none;
    }
    const std::string& x509_root_path   {params_.at("UA_CA_CRT_PATH").as_string().c_str()};
    const std::string& x509_client_path {params_.at("UA_CLIENT_CRT_PATH").as_string().c_str()};
    const std::string& PKEY_client_path {params_.at("UA_CLIENT_KEY_PATH").as_string().c_str()};

    std::string PKEY_client_pass {};
    if(params_.contains("UA_CLIENT_KEY_PASS")){
        PKEY_client_pass=params_.at("UA_CLIENT_KEY_PASS").as_string().c_str();
    }

    boost::system::error_code ec;
    boost::asio::ssl::context ctx {boost::asio::ssl::context_base::sslv23_client};
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    ctx.use_certificate_chain_file(x509_root_path,ec);
    ctx.use_certificate_file(x509_client_path,boost::asio::ssl::context::pem,ec);
    ctx.set_password_callback([&](std::size_t max_length,boost::asio::ssl::context::password_purpose purpose){
        return PKEY_client_pass;
    });
    ctx.use_private_key_file(PKEY_client_path,boost::asio::ssl::context::pem,ec);

    if(ec){
        return boost::none;
    }
    return ctx;
}

https_client::https_client(boost::asio::io_context &io,
    const std::string& app_dir, const boost::json::object &params, std::shared_ptr<spdlog::logger> logger_ptr)
    :io_{io},app_dir_{app_dir},params_{params},logger_ptr_{logger_ptr}
{
}

https_client::~https_client()
{
    boost::system::error_code ec;
    io_.stop();
}

void https_client::client_run()
{
    boost::optional<boost::asio::ssl::context> ctx {make_context()};
    if(!ctx){
        const std::string& msg {"https_client init ssl_context fail"};
        if(uc_status_signal_){
            uc_status_signal_(uc_status::fail,msg);
        }
        return;
    }

    const std::string& UA_UC_HOST {params_.at("UA_UC_HOST").as_string().c_str()};
    const std::string& UA_UC_PORT {params_.at("UA_UC_PORT").as_string().c_str()};

    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver resolvser {io_};
    const auto& results {resolvser.resolve(UA_UC_HOST,UA_UC_PORT,ec)};
    if(ec){
        if(uc_status_signal_){
            uc_status_signal_(uc_status::fail,ec.message());
        }
        return;
    }

    boost::beast::ssl_stream<boost::asio::ip::tcp::socket> socket_ {io_,ctx.value()};
    boost::beast::get_lowest_layer(socket_).connect(*results.begin(),ec);
    if(ec){
        if(uc_status_signal_){
            uc_status_signal_(uc_status::bad_gateway,ec.message());
        }
        return;
    }
    socket_.set_verify_callback([&](bool preverified,boost::asio::ssl::verify_context& ctx){
        return true;
    });
    socket_.handshake(boost::asio::ssl::stream_base::client,ec);
    if(ec){
        if(uc_status_signal_){
            uc_status_signal_(uc_status::bad_gateway,ec.message());
        }
        return;
    }
    if(! SSL_set_tlsext_host_name(socket_.native_handle(), UA_UC_HOST.c_str())){
        return;
    }
    socket_.set_verify_callback([&](bool preverified,boost::asio::ssl::verify_context& ctx){
        return true;
    });

    boost::beast::http::request<boost::beast::http::string_body> request{boost::beast::http::verb::get, "/integrity", 11};
    request.set(boost::beast::http::field::host, UA_UC_HOST);
    request.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    boost::beast::http::write(socket_,request,ec);
    if(ec){
        if(uc_status_signal_){
            uc_status_signal_(uc_status::bad_gateway,ec.message());
        }
        return;
    }

    boost::beast::flat_buffer buffer;
    boost::beast::http::response<boost::beast::http::string_body> response;
    boost::beast::http::read(socket_, buffer, response,ec);

    const boost::json::value& v {boost::json::parse(response.body(),ec)};
    if(ec || !v.is_object()){
        if(uc_status_signal_){
            uc_status_signal_(uc_status::failed_dependency,ec.message());
        }
        socket_.shutdown(ec);
        return;

    }
    const boost::json::object& body_obj {v.as_object()};
    if(!body_obj.contains("integrity")){
        if(uc_status_signal_){
            uc_status_signal_(uc_status::failed_dependency,ec.message());
        }
        socket_.shutdown(ec);
        return;
    }
    const bool& success {body_obj.at("integrity").as_bool()};
    uc_status status {success ? uc_status::success : uc_status::failed_dependency};
    uc_status_signal_(status,ec.message());
    socket_.shutdown(ec);
}

