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
#include <boost/format.hpp>
#include <boost/beast/http.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/beast/http/message_generator.hpp>

#include "spdlog/logger.h"

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
    http::response<http::string_body> handle_user(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_authz(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_authz_manage(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_rp(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_certificate(http::request<http::string_body>&& request,const std::string& requester_id);

    //user verb handlers
    http::response<http::string_body> handle_user_get(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_user_put(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_user_post(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_user_delete(http::request<http::string_body>&& request,const std::string& requester_id);

    //authz verb handlers
    http::response<http::string_body> handle_authz_get(http::request<http::string_body>&& request,const std::string& requester_id);

    //authz-manage verb handlers
    http::response<http::string_body> handle_authz_manage_post(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_authz_manage_delete(http::request<http::string_body>&& request,const std::string& requester_id);

    //rp varb handlers
    http::response<http::string_body> handle_rp_get(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_rp_put(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_rp_post(http::request<http::string_body>&& request,const std::string& requester_id);
    http::response<http::string_body> handle_rp_delete(http::request<http::string_body>&& request,const std::string& requester_id);

    //certificate verb handler
    http::response<http::string_body> handle_certificate_post(http::request<http::string_body>&& request,const std::string& requester_id);

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
        {//log request
            if(logger_ptr_){
                const std::string& body {request.body()};
                const std::string& msg {(boost::format("method: %s, target: %s, body: %s")
                                                       % request.method_string()
                                                       % request.target()
                                                       % body).str()};
                logger_ptr_->debug("request log, {}",msg);
            }
        }
        http::response<http::string_body> response {fail(std::move(request),http::status::not_found,"not found")};
        {//handle user
            if(boost::starts_with(target,"/api/v1/u-auth/users")){
                response=handle_user(std::move(request),requester_id);
                goto log;
            }
        }
        {//handle authz-manage
            if(boost::starts_with(target,"/api/v1/u-auth/authz/manage")){
                response=handle_authz_manage(std::move(request),requester_id);
                goto log;
            }
        }
        {//handle authz
            if(boost::starts_with(target,"/api/v1/u-auth/authz")){
                response=handle_authz(std::move(request),requester_id);
                goto log;
            }
        }
        {//handle rp
            if(boost::starts_with(target,"/api/v1/u-auth/roles-permissions")){
                response=handle_rp(std::move(request),requester_id);
                goto log;
            }
        }
        {//handle certificate
            if(boost::starts_with(target,"/api/v1/u-auth/certificates")){
                response=handle_certificate_post(std::move(request),requester_id);
                goto log;
            }
        }
        log:
        {//log response
            if(logger_ptr_){
                const std::string& body {response.body()};
                const std::string& msg {(boost::format("body: %s")
                                        % body).str()};
                logger_ptr_->debug("response log, {}",msg);
            }
        }
        return response;
    }
};

#endif // HTTP_HANDLER_H
