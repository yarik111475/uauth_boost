#include "http_handler.h"
#include "dbase/dbase_handler.h"
#include "x509/x509_generator.h"

#include <algorithm>
#include <boost/url.hpp>
#include <boost/json.hpp>
#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>
#include "spdlog/spdlog.h"

http::response<http::string_body> http_handler::fail(http::request<http::string_body> &&request,http::status code,const std::string &body)
{
    body_ptr_.reset(new std::string{body});
    http::response<http::string_body> response {code,request.version()};
    response.keep_alive(request.keep_alive());
    response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    response.set(http::field::content_type,"application/json");
    response.set(http::field::content_length,std::to_string(body_ptr_->size()));
    response.body()=*body_ptr_;
    response.prepare_payload();
    return response;
}

http::response<http::string_body> http_handler::success(http::request<http::string_body> &&request,http::status code, const std::string &body)
{
    body_ptr_.reset(new std::string{body});
    http::response<http::string_body> response {code,request.version()};
    response.keep_alive(request.keep_alive());
    response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    response.set(http::field::content_type,"application/json");
    response.set(http::field::content_length,std::to_string(body_ptr_->size()));
    response.body()=*body_ptr_;
    response.prepare_payload();
    return response;
}

http::response<http::string_body> http_handler::handle_users(http::request<http::string_body> &&request, const std::string &requester_id)
{
    //verb check
    if((request.method()!=http::verb::get) & (request.method()!=http::verb::put) &
       (request.method()!=http::verb::post) & (request.method()!=http::verb::delete_)){
        return fail(std::move(request),http::status::not_found,"not found");
    }
    switch(request.method()){
    case http::verb::get:
        return handle_users_get(std::move(request),requester_id);
        break;
    case http::verb::put:
        return handle_users_put(std::move(request),requester_id);
        break;
    case http::verb::post:
        return handle_users_post(std::move(request),requester_id);
        break;
    case http::verb::delete_:
        return handle_users_delete(std::move(request),requester_id);
        break;
    default:
        return fail(std::move(request),http::status::not_found,"not found");
        break;
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_authz(http::request<http::string_body> &&request, const std::string &requester_id)
{
    //verb check
    if(request.method()!=http::verb::get){
        return fail(std::move(request),http::status::bad_request,"bad request");
    }
    return handle_authz_get(std::move(request),requester_id);
}

http::response<http::string_body> http_handler::handle_authz_manage(http::request<http::string_body> &&request, const std::string &requester_id)
{
    //verb check
    if((request.method()!=http::verb::post) & (request.method()!=http::verb::delete_)){
        return fail(std::move(request),http::status::not_found,"not found");
    }
    switch(request.method()){
    case http::verb::post:
        return handle_authz_manage_post(std::move(request),requester_id);
        break;
    case http::verb::delete_:
        return handle_authz_manage_delete(std::move(request),requester_id);
        break;
    default:
        return fail(std::move(request),http::status::not_found,"not found");
        break;
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_rps(http::request<http::string_body> &&request, const std::string &requester_id)
{
    //verb check
    if((request.method()!=http::verb::get) & (request.method()!=http::verb::put) &
       (request.method()!=http::verb::post) & (request.method()!=http::verb::delete_)){
        return fail(std::move(request),http::status::not_found,"not found");
    }
    switch(request.method()){
    case http::verb::get:
        return handle_rps_get(std::move(request),requester_id);
        break;
    case http::verb::put:
        return handle_rps_put(std::move(request),requester_id);
        break;
    case http::verb::post:
        return handle_rps_post(std::move(request),requester_id);
        break;
    case http::verb::delete_:
        return handle_rps_delete(std::move(request),requester_id);
        break;
    default:
        return fail(std::move(request),http::status::not_found,"not found");
        break;
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_certificates(http::request<http::string_body> &&request, const std::string &requester_id)
{
    if(request.method()==http::verb::post){
        return handle_certificates_post(std::move(request),requester_id);
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_users_get(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    {//users list
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"users:read"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/users$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            std::string msg {};
            std::string users {};
            const bool& ok {dbase_handler_ptr_->users_list_get(users,msg)};
            if(ok){
                return success(std::move(request),http::status::ok,users);
            }
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    {//user by user_uid
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"users:read"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/users/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& user_uid {match[1]};
            std::string msg {};
            std::string user {};
            const bool& ok {dbase_handler_ptr_->users_info_get(user_uid,user,msg)};
            if(ok){
                return success(std::move(request),http::status::ok,user);
            }
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    {//user's roles_permissions
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"roles_permissions:read"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/users/" + regex_uid_ + "/roles-permissions$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& user_uid {match[1]};
            std::string msg {};
            std::string rps {};
            const bool& ok {dbase_handler_ptr_->users_rps_get(user_uid,rps,msg)};
            if(ok){
                return success(std::move(request),http::status::ok,rps);
            }
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    {//list with limit and/or offset and filter
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"users:read"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        std::string limit {};
        std::string offset {};
        std::string first_name {};
        std::string last_name {};
        std::string email {};
        std::string is_blocked {};
        boost::url url_ {target};
        auto query=url_.query();
        if(!query.empty()){
            boost::urls::result<boost::urls::params_encoded_view> result=boost::urls::parse_query(query);
            if(!result.has_error()){
                const boost::urls::params_encoded_view& view {result.value()};
                if(view.contains("limit")){
                    auto it {view.find("limit")};
                    limit=std::string {it->value};
                }
                if(view.contains("offset")){
                    auto it {view.find("offset")};
                    offset=std::string {it->value};
                }
                if(view.contains("first_name")){
                    auto it {view.find("first_name")};
                    first_name=std::string {it->value};
                }
                if(view.contains("last_name")){
                    auto it {view.find("last_name")};
                    last_name=std::string {it->value};
                }
                if(view.contains("email")){
                    auto it {view.find("email")};
                    email=std::string {it->value};
                }
                if(view.contains("is_blocked")){
                    auto it {view.find("is_blocked")};
                    is_blocked=std::string {it->value};
                }

                std::string msg {};
                std::string users {};
                const bool& ok {dbase_handler_ptr_->users_list_get(users,limit,offset,first_name,last_name,email,is_blocked,msg)};
                if(ok){
                    return success(std::move(request),http::status::ok,users);
                }
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_users_put(http::request<http::string_body> &&request, const std::string &requester_id)
{
    {//check if authorized
        std::string msg {};
        const std::string& rp_name {"users:update"};
        const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
        if(!allowed){
            return fail(std::move(request),http::status::unauthorized,"unauthorized");
        }
    }
    const std::string& target {request.target()};
    boost::regex re {"^/api/v1/u-auth/users/" + regex_uid_ + "$"};
    boost::smatch match;
    if(boost::regex_match(target,match,re)){
        const std::string& user_uid {match[1]};
        const std::string& body {request.body()};

        boost::system::error_code ec;
        const boost::json::value v {boost::json::parse(body,ec)};
        if(ec || !v.is_object()){
            return fail(std::move(request),http::status::bad_request,"not valid user");
        }
        const boost::json::object& user {v.as_object()};
        if(!user.contains("first_name") ||!user.contains("last_name")|| !user.contains("email") || !user.contains("is_blocked") ||
           !user.contains("phone_number") || !user.contains("position") || !user.contains("gender") || !user.contains("location_id") || !user.contains("ou_id")){
            return fail(std::move(request),http::status::bad_request,"not valid user");
        }

        std::string msg;
        const bool& ok {dbase_handler_ptr_->users_info_put(user_uid,body,msg)};
        if(ok){
            return success(std::move(request),http::status::ok,msg);
        }
        return fail(std::move(request),http::status::bad_request,"bad request");
    }

    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_users_post(http::request<http::string_body> &&request, const std::string &requester_id)
{
    {//check if authorized
        std::string msg {};
        const std::string& rp_name {"users:create"};
        const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
        if(!allowed){
            return fail(std::move(request),http::status::unauthorized,"unauthorized");
        }
    }
    const std::string& body {request.body()};
    boost::system::error_code ec;
    const boost::json::value v {boost::json::parse(body,ec)};
    if(ec || !v.is_object()){
        return fail(std::move(request),http::status::bad_request,"not valid user");
    }
    const boost::json::object& user {v.as_object()};
    if(!user.contains("first_name") ||!user.contains("last_name")|| !user.contains("email") || !user.contains("phone_number") ||
        !user.contains("position") || !user.contains("gender") || !user.contains("location_id") || !user.contains("ou_id")){
        return fail(std::move(request),http::status::bad_request,"not valid user");
    }

    std::string msg;
    const bool& ok {dbase_handler_ptr_->users_info_post(body,msg)};
    if(ok){
        return success(std::move(request),http::status::ok,"user created");
    }
    return fail(std::move(request),http::status::not_found,msg);
}

http::response<http::string_body> http_handler::handle_users_delete(http::request<http::string_body> &&request, const std::string &requester_id)
{
    {//check if authorized
        std::string msg {};
        const std::string& rp_name {"users:delete"};
        const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
        if(!allowed){
            return fail(std::move(request),http::status::unauthorized,"unauthorized");
        }
    }
    const std::string& target {request.target()};
    boost::regex re {"^/api/v1/u-auth/users/" + regex_uid_ + "$"};
    boost::smatch match;
    if(!boost::regex_match(target,match,re)){
        return fail(std::move(request),http::status::bad_request,"bad request");
    }
    const std::string& user_uid {match[1]};
    std::string msg;
    const bool& ok {dbase_handler_ptr_->users_info_delete(user_uid,msg)};
    if(ok){
        return success(std::move(request),http::status::no_content,msg);
    }
    return fail(std::move(request),http::status::not_found,msg);
}

http::response<http::string_body> http_handler::handle_authz_get(http::request<http::string_body> &&request, const std::string &requester_id)
{
    boost::ignore_unused(requester_id);
    const std::string& target {request.target()};
    boost::regex re {"^/api/v1/u-auth/authz/" + regex_uid_+ "/authorized-to/" + regex_any_ + "$"};
    boost::smatch match;
    if(boost::regex_match(target,match,re)){
        const std::string& user_uid {match[1]};
        const std::string& rp_ident {match[2]};
        std::string msg {};
        {//check roles_permissions
            const bool& ok {dbase_handler_ptr_->authz_check_get(user_uid,rp_ident,msg)};
            return success(std::move(request),http::status::ok,std::to_string(ok));
        }
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_authz_manage_post(http::request<http::string_body> &&request, const std::string &requester_id)
{
    {//check if authorized
        std::string msg {};
        const std::string& rp_name {"authorization_manage"};
        const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
        if(!allowed){
            return fail(std::move(request),http::status::unauthorized,"unauthorized");
        }
    }
    const std::string& target {request.target()};
    boost::regex re {"^/api/v1/u-auth/authz/manage/" + regex_uid_ + "/assign/" + regex_uid_ + "$"};
    boost::smatch match;
    if(boost::regex_match(target,match,re)){
        const std::string& requested_user_id {match[1]};
        const std::string& requested_rp_id {match[2]};
        std::string msg {};

        const bool& ok {dbase_handler_ptr_->authz_manage_post(requested_user_id,requested_rp_id,msg)};
        if(ok){
            return success(std::move(request),http::status::ok,msg);
        }
        return fail(std::move(request),http::status::not_found,msg);
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_authz_manage_delete(http::request<http::string_body> &&request, const std::string &requester_id)
{
    {//check if authorized
        std::string msg {};
        const std::string& rp_name {"authorization_manage"};
        const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
        if(!allowed){
            return fail(std::move(request),http::status::unauthorized,"unauthorized");
        }
    }
    const std::string& target {request.target()};
    boost::regex re {"^/api/v1/u-auth/authz/manage/" + regex_uid_ + "/revoke/" + regex_uid_ + "$"};
    boost::smatch match;
    if(boost::regex_match(target,match,re)){
        const std::string& requested_user_id {match[1]};
        const std::string& requested_rp_id {match[2]};
        std::string msg {};

        const bool& ok {dbase_handler_ptr_->authz_manage_delete(requested_user_id,requested_rp_id,msg)};
        if(ok){
            return success(std::move(request),http::status::ok,msg);
        }
        return fail(std::move(request),http::status::not_found,msg);
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_rps_get(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    {//rps list
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"roles_permissions:read"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/roles-permissions$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            std::string msg {};
            std::string rps {};
            const bool& ok {dbase_handler_ptr_->rps_list_get(rps,msg)};
            if(ok){
                return success(std::move(request),http::status::ok,rps);
            }
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    {//rps by rp_uid
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"roles_permissions:read"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& rp_uid {match[1]};
            std::string msg {};
            std::string rp {};
            const bool& ok {dbase_handler_ptr_->rps_info_get(rp_uid,rp,msg)};
            if(ok){
                return success(std::move(request),http::status::ok,rp);
            }
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    {//rps details
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"roles_permissions:read"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "/detail$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& rp_uid {match[1]};
            std::string msg {};
            std::string rp_detail {};
            const bool& ok {dbase_handler_ptr_->rps_rp_detail_get(rp_uid,rp_detail,msg)};
            if(ok){
                return success(std::move(request),http::status::ok,rp_detail);
            }
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    {//all users for rps by rps_uid
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"users:read"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "/associated-users$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& rp_uid {match[1]};
            std::string msg {};
            std::string users {};
            const bool& ok {dbase_handler_ptr_->rps_users_get(rp_uid,users,msg)};
            if(ok){
                return success(std::move(request),http::status::ok,users);
            }
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    {//all users for rps by rps_uid with limit and/or offset
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"users:read"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "/associated-users?" + regex_any_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& rp_uid {match[1]};

            std::string limit {};
            std::string offset {};
            boost::url url_ {target};
            auto query=url_.query();
            if(!query.empty()){
                boost::urls::result<boost::urls::params_encoded_view> result=boost::urls::parse_query(query);
                if(!result.has_error()){
                    const boost::urls::params_encoded_view& view {result.value()};
                    if(view.contains("limit")){
                        auto it {view.find("limit")};
                        limit=std::string {it->value};
                    }
                    if(view.contains("offset")){
                        auto it {view.find("offset")};
                        offset=std::string {it->value};
                    }

                    std::string msg {};
                    std::string users {};
                    const bool& ok {dbase_handler_ptr_->rps_users_get(rp_uid,users,limit,offset,msg)};
                    if(ok){
                        return success(std::move(request),http::status::ok,users);
                    }
                    return fail(std::move(request),http::status::bad_request,msg);
                }
            }
        }
    }
    {//list with limit and/or offset and filter
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"roles_permissions:read"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        std::string limit {};
        std::string offset {};
        std::string name {};
        std::string type {};
        std::string description {};
        boost::url url_ {target};
        auto query=url_.query();
        if(!query.empty()){
            boost::urls::result<boost::urls::params_encoded_view> result=boost::urls::parse_query(query);
            if(!result.has_error()){
                const boost::urls::params_encoded_view& view {result.value()};
                if(view.contains("limit")){
                    auto it {view.find("limit")};
                    limit=std::string {it->value};
                }
                if(view.contains("offset")){
                    auto it {view.find("offset")};
                    offset=std::string {it->value};
                }
                if(view.contains("name")){
                    auto it {view.find("name")};
                    name=std::string {it->value};
                }
                if(view.contains("type")){
                    auto it {view.find("type")};
                    type=std::string {it->value};
                }
                if(view.contains("description")){
                    auto it {view.find("description")};
                    description=std::string {it->value};
                }

                std::string msg {};
                std::string rps {};
                const bool& ok {dbase_handler_ptr_->rps_list_get(rps,limit,offset,name,type,description,msg)};
                if(ok){
                    return success(std::move(request),http::status::ok,rps);
                }
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }

    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_rps_put(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    {//update role_permission
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"roles_permissions:update"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& rp_uid {match[1]};
            const std::string& body {request.body()};

            boost::system::error_code ec;
            const boost::json::value v {boost::json::parse(body,ec)};
            if(ec || !v.is_object()){
                return fail(std::move(request),http::status::bad_request,"not valid role-permission");
            }
            const boost::json::object& rp {v.as_object()};
            if(!rp.contains("name") ||!rp.contains("type")|| !rp.contains("description")){
                return fail(std::move(request),http::status::bad_request,"not valid role-permission");
            }

            std::string msg;
            const bool& ok {dbase_handler_ptr_->rps_info_put(rp_uid,body,msg)};
            if(ok){
                return success(std::move(request),http::status::ok,msg);
            }
            return fail(std::move(request),http::status::not_found,msg);
        }
    }
    {//add role_permission relationship
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"roles_permissions:update"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "/add-child/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& parent_uid {match[1]};
            const std::string& child_uid {match[2]};
            std::string msg;
            const bool& ok {dbase_handler_ptr_->rps_child_put(parent_uid,child_uid,msg)};
            if(ok){
                return success(std::move(request),http::status::ok,msg);
            }
            return fail(std::move(request),http::status::not_found,msg);
        }
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_rps_post(http::request<http::string_body> &&request, const std::string &requester_id)
{
    {//check if authorized
        std::string msg {};
        const std::string& rp_name {"roles_permissions:create"};
        const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
        if(!allowed){
            return fail(std::move(request),http::status::unauthorized,"unauthorized");
        }
    }
    const std::string& body {request.body()};
    boost::system::error_code ec;
    const boost::json::value v {boost::json::parse(body,ec)};
    if(ec || !v.is_object()){
        return fail(std::move(request),http::status::not_found,"not valid role-permission");
    }
    const boost::json::object& user {v.as_object()};
    if(!user.contains("name")|| !user.contains("type") || !user.contains("description")){
        return fail(std::move(request),http::status::not_found,"not valid role-permission");
    }

    std::string msg;
    const bool& ok {dbase_handler_ptr_->rps_info_post(body,msg)};
    if(ok){
        return success(std::move(request),http::status::ok,msg);
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_rps_delete(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    {//remove role_permission
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"roles_permissions:delete"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& rp_uid {match[1]};
            std::string msg;
            const bool& ok {dbase_handler_ptr_->rps_info_delete(rp_uid,msg)};
            if(ok){
                return success(std::move(request),http::status::no_content,msg);
            }
            return fail(std::move(request),http::status::not_found,msg);
        }
    }
    {//remove role_permission relationship
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"roles_permissions:update"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "/remove-child/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& parent_uid {match[1]};
            const std::string& child_uid {match[2]};
            std::string msg;
            const bool& ok {dbase_handler_ptr_->rps_child_delete(parent_uid,child_uid,msg)};
            if(ok){
                return success(std::move(request),http::status::ok,msg);
            }
            return fail(std::move(request),http::status::not_found,msg);
        }
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_certificates_post(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    {//handle user certificate
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"user_certificates"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/certificates/user/" + regex_uid_ + "?" + regex_any_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){//get fields from target
            const std::string& user_id {match[1]};
            std::string pkcs_pass {};

            boost::url url_ {target};
            auto query=url_.query();
            if(!query.empty()){//check query
                boost::urls::result<boost::urls::params_encoded_view> result=boost::urls::parse_query(query);
                if(!result.has_error()){
                    const boost::urls::params_encoded_view& view {result.value()};
                    if(view.contains("certificate_password")){
                        auto it {view.find("certificate_password")};
                        pkcs_pass=std::string {it->value};
                    }
                    else{
                        return fail(std::move(request),http::status::bad_request,"bad request");
                    }
                }
            }

            std::string user_email {};
            {//check user by user_id and get user email
                std::string msg {};
                std::string user {};
                const bool& ok {dbase_handler_ptr_->users_info_get(user_id,user,msg)};
                if(!ok){
                    return fail(std::move(request),http::status::not_found,msg);
                }
                boost::system::error_code ec;
                const boost::json::value& v {boost::json::parse(user,ec)};
                if(ec || !v.is_object()){
                    return fail(std::move(request),http::status::not_found,"not valid user");
                }
                const boost::json::object& user_obj {v.as_object()};
                user_email=user_obj.at("email").as_string().c_str();
            }

            const std::string& pkcs_name {"pkcs"};
            const std::string& root_path {params_.at("UA_CA_CRT_PATH").as_string().c_str()};
            const std::string& pub_path {params_.at("UA_SIGNING_CA_CRT_PATH").as_string().c_str()};
            const std::string& pr_path {params_.at("UA_SIGNING_CA_KEY_PATH").as_string().c_str()};
            const std::string& pr_pass {params_.at("UA_SIGNING_CA_KEY_PASS").as_string().c_str()};

            std::string msg {};
            std::vector<char> PKCS12_content {};
            std::shared_ptr<x509_generator> x509 {new x509_generator(logger_ptr_)};
            const bool& ok {x509->create_PKCS12(user_id,root_path,pub_path,pr_path,pr_pass,pkcs_pass,pkcs_name,PKCS12_content,msg)};
            if(ok){
                std::string body {PKCS12_content.begin(),PKCS12_content.end()};
                body_ptr_.reset(new std::string {body});
                http::response<http::string_body> response {http::status::ok,request.version()};
                response.keep_alive(request.keep_alive());
                response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                response.set(http::field::content_type,"application/x-pkcs12");
                response.set(http::field::content_length,std::to_string(body_ptr_->size()));
                response.set(http::field::content_disposition,"attachment;filename=" + user_email + ".pfx");
                response.body()=*body_ptr_;
                response.prepare_payload();
                return response;
            }
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    {//handle agent certificate
        {//check if authorized
            std::string msg {};
            const std::string& rp_name {"agent_certificates"};
            const bool& allowed {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,msg)};
            if(!allowed){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/certificates/agent/sign-csr$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& content {request.body()};
            const std::vector<char>& x509_REQ_content {content.begin(),content.end()};
            const std::string& pub_path {params_.at("UA_SIGNING_CA_CRT_PATH").as_string().c_str()};
            const std::string& pr_path {params_.at("UA_SIGNING_CA_KEY_PATH").as_string().c_str()};
            const std::string& pr_pass {params_.at("UA_SIGNING_CA_KEY_PASS").as_string().c_str()};

            std::string msg {};
            std::vector<char> x509_content {};
            std::shared_ptr<x509_generator> x509 {new x509_generator(logger_ptr_)};
            const bool& ok {x509->create_X509(pub_path,pr_path,pr_pass,x509_REQ_content,x509_content,msg)};
            if(ok){
                std::string body {x509_content.begin(),x509_content.end()};
                body_ptr_.reset(new std::string {body});
                http::response<http::string_body> response {http::status::ok,request.version()};
                response.keep_alive(request.keep_alive());
                response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                response.set(http::field::content_type,"application/pem-certificate-chain");
                response.set(http::field::content_length,std::to_string(body_ptr_->size()));
                response.set(http::field::content_disposition,"attachment;filename=agent_certificate.pem");
                response.body()=*body_ptr_;
                response.prepare_payload();
                return response;
            }
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http_handler::http_handler(const boost::json::object &params, std::shared_ptr<spdlog::logger> logger_ptr)
    :params_{params},logger_ptr_{logger_ptr}
{
    {//init dbase_handler
        dbase_handler_ptr_.reset(new dbase_handler{params_,logger_ptr});
    }
}

