#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H
#include "defines.h"
#include "dbase/dbase_handler.h"

#include <map>
#include <string>
#include <memory>
#include <functional>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/beast/http/message_generator.hpp>

namespace spdlog{
    class logger;
}

using namespace boost::beast;

class http_handler
{
private:
    uc_status status_ {uc_status::fail};
    const std::string regex_any_ {"([\\s\\S]+)"};
    const std::string regex_uid_ {"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"};
    boost::json::object params_ {};

    //error handlers
    http::response<http::string_body> fail(http::request<http::string_body>&& request,http::status code,const std::string& body);
    http::response<http::string_body> success(http::request<http::string_body>&& request, http::status code, const std::string& body);

    //rote handlers
    http::response<http::string_body> handle_users(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_authz(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_authz_manage(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_rps(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_certificates(http::request<http::string_body>&& request,const std::string& requester_id);

    //users verb handlers
    http::response<http::string_body> handle_users_get(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_users_put(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_users_post(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_users_delete(http::request<http::string_body>&& request,const std::string& requester_id);

    //authz verb handlers
    http::response<http::string_body> handle_authz_get(http::request<http::string_body>&& request,const std::string& requester_id);

    //authz-manage verb handlers
    http::response<http::string_body> handle_authz_manage_post(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_authz_manage_delete(http::request<http::string_body>&& request,const std::string& requester_id);

    //rps varb handlers
    http::response<http::string_body> handle_rps_get(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_rps_put(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_rps_post(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_rps_delete(http::request<http::string_body>&& request,const std::string& requester_id);

    //certificate verb handler
    http::response<http::string_body> handle_certificates_post(http::request<http::string_body>&& request,const std::string& requester_id);

    std::shared_ptr<std::string> body_ptr_ {nullptr};
    std::shared_ptr<dbase_handler> dbase_handler_ptr_ {nullptr};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};

public:
    explicit http_handler(const boost::json::object& params,uc_status status,std::shared_ptr<spdlog::logger> logger_ptr);
    ~http_handler()=default;

    template <class Body, class Allocator>
    http::message_generator handle_request(http::request<Body, http::basic_fields<Allocator>>&& request){
        {//handle uc_status
            switch(status_){
            case uc_status::fail:
                return fail(std::move(request),http::status::bad_request,"bad_request");
            case uc_status::success:
                break;
            case uc_status::bad_gateway:
                return fail(std::move(request),http::status::bad_gateway,"bad_gateway");
            case uc_status::failed_dependency:
                return fail(std::move(request),http::status::failed_dependency,"failed_dependency");
            }
        }
        std::string msg {};
        std::string requester_id {};
        const std::string& target {request.target()};

        {//check headers and get requester_id
            const auto& headers {request.base()};
            const auto& it {headers.find("X-Client-Cert-Dn")};
            if(it==headers.end()){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
            requester_id=it->value();
        }

        {//check and init database
            const bool& db_ok {dbase_handler_ptr_->init_database(msg)};
            if(!db_ok){
                return fail(std::move(request),http::status::internal_server_error,msg);
            }
        }
        {//handle users
            if(boost::starts_with(target,"/api/v1/u-auth/users")){
                return handle_users(std::move(request),requester_id);
            }
        }
        {//handle authz-manage
            if(boost::starts_with(target,"/api/v1/u-auth/authz/manage")){
                return handle_authz_manage(std::move(request),requester_id);
            }
        }
        {//handle authz
            if(boost::starts_with(target,"/api/v1/u-auth/authz")){
                return handle_authz(std::move(request),requester_id);
            }
        }
        {//handle rps
            if(boost::starts_with(target,"/api/v1/u-auth/roles-permissions")){
                return handle_rps(std::move(request),requester_id);
            }
        }
        {//handle certificates
            if(boost::starts_with(target,"/api/v1/u-auth/certificates")){
                return handle_certificates_post(std::move(request),requester_id);
            }
        }
        return fail(std::move(request),http::status::not_found,"not found");
    }
};

#endif // HTTP_HANDLER_H
