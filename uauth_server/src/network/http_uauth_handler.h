#ifndef UAUTH_HANDLER_H
#define UAUTH_HANDLER_H

#include <map>
#include <string>
#include <memory>
#include <functional>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace spdlog{
    class logger;
}

class dbase_handler;

typedef boost::beast::http::request<boost::beast::http::string_body> request_t;
typedef boost::beast::http::response<boost::beast::http::string_body> response_t;

class http_uauth_handler
{
private:
    const std::string regex_any_ {"([\\s\\S]+)"};
    const std::string regex_uid_ {"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"};
    boost::json::object params_ {};

    //error handlers
    response_t fail(request_t&& request,boost::beast::http::status code,const std::string& body);
    response_t success(request_t&& request, boost::beast::http::status code, const std::string& body);

    //rote handlers
    response_t handle_users(request_t&& request);
    response_t handle_authz(request_t&& request);
    response_t handle_authz_manage(request_t&& request);
    response_t handle_rps(request_t&& request);
    response_t handle_certificates(request_t&& request);

    //users verb handlers
    response_t handle_users_get(request_t&& request);
    response_t handle_users_put(request_t&& request);
    response_t handle_users_post(request_t&& request);
    response_t handle_users_delete(request_t&& request);

    //authz verb handlers
    response_t handle_authz_get(request_t&& request);

    //authz-manage verb handlers
    response_t handle_authz_manage_post(request_t&& request);
    response_t handle_authz_manage_delete(request_t&& request);

    //rps varb handlers
    response_t handle_rps_get(request_t&& request);
    response_t handle_rps_put(request_t&& request);
    response_t handle_rps_post(request_t&& request);
    response_t handle_rps_delete(request_t&& request);

    //certificate verb handler
    response_t handle_certificates_post(request_t&& request);

    std::shared_ptr<std::string> body_ptr_ {nullptr};
    std::shared_ptr<dbase_handler> dbase_handler_ptr_ {nullptr};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};

public:
    explicit http_uauth_handler(const boost::json::object& params,std::shared_ptr<spdlog::logger> logger_ptr);
    ~http_uauth_handler()=default;
    response_t handle_request(request_t&& request);;
};

#endif // UAUTH_HANDLER_H
