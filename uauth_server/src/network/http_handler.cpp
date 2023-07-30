#include "http_handler.h"
#include "dbase/dbase_handler.h"

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

http::response<http::string_body> http_handler::handle_users(http::request<http::string_body> &&request)
{
    //verb check
    if((request.method()!=http::verb::get) & (request.method()!=http::verb::put) &
       (request.method()!=http::verb::post) & (request.method()!=http::verb::delete_)){
        return fail(std::move(request),http::status::not_found,"not found");
    }
    switch(request.method()){
    case http::verb::get:
        return handle_users_get(std::move(request));
        break;
    case http::verb::put:
        return handle_users_put(std::move(request));
        break;
    case http::verb::post:
        return handle_users_post(std::move(request));
        break;
    case http::verb::delete_:
        return handle_users_delete(std::move(request));
        break;
    default:
        return fail(std::move(request),http::status::not_found,"not found");
        break;
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_authz(http::request<http::string_body> &&request)
{
    //verb check
    if(request.method()!=http::verb::get){
        return fail(std::move(request),http::status::bad_request,"bad request");
    }
    return handle_authz_get(std::move(request));
}

http::response<http::string_body> http_handler::handle_authz_manage(http::request<http::string_body> &&request)
{
    //verb check
    if((request.method()!=http::verb::post) & (request.method()!=http::verb::delete_)){
        return fail(std::move(request),http::status::not_found,"not found");
    }
    switch(request.method()){
    case http::verb::post:
        return handle_authz_manage_post(std::move(request));
        break;
    case http::verb::delete_:
        return handle_authz_manage_delete(std::move(request));
        break;
    default:
        return fail(std::move(request),http::status::not_found,"not found");
        break;
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_rps(http::request<http::string_body> &&request)
{
    //verb check
    if((request.method()!=http::verb::get) & (request.method()!=http::verb::put) &
       (request.method()!=http::verb::post) & (request.method()!=http::verb::delete_)){
        return fail(std::move(request),http::status::not_found,"not found");
    }
    switch(request.method()){
    case http::verb::get:
        return handle_rps_get(std::move(request));
        break;
    case http::verb::put:
        return handle_rps_put(std::move(request));
        break;
    case http::verb::post:
        return handle_rps_post(std::move(request));
        break;
    case http::verb::delete_:
        return handle_rps_delete(std::move(request));
        break;
    default:
        return fail(std::move(request),http::status::not_found,"not found");
        break;
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_certificates(http::request<http::string_body> &&request)
{
    if(request.method()==http::verb::post){
        return handle_certificates_post(std::move(request));
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_users_get(http::request<http::string_body> &&request)
{
    const std::string& target {request.target()};
    {//list without pagination
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

http::response<http::string_body> http_handler::handle_users_put(http::request<http::string_body> &&request)
{
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

http::response<http::string_body> http_handler::handle_users_post(http::request<http::string_body> &&request)
{
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

http::response<http::string_body> http_handler::handle_users_delete(http::request<http::string_body> &&request)
{
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

http::response<http::string_body> http_handler::handle_authz_get(http::request<http::string_body> &&request)
{
    const std::string& target {request.target()};
    boost::regex re {"^/api/v1/u-auth/authz/" + regex_uid_+ "/authorized-to/" + regex_any_ + "$"};
    boost::smatch match;
    if(boost::regex_match(target,match,re)){
        const std::string& user_uid {match[1]};
        const std::string& rp_ident {match[2]};
        std::string msg {};
        const bool& ok {dbase_handler_ptr_->authz_check_get(user_uid,rp_ident,msg)};
        if(ok){
            return success(std::move(request),http::status::ok,std::to_string(true));
        }
        return fail(std::move(request),http::status::not_found,msg);
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_authz_manage_post(http::request<http::string_body> &&request)
{
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

http::response<http::string_body> http_handler::handle_authz_manage_delete(http::request<http::string_body> &&request)
{
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

http::response<http::string_body> http_handler::handle_rps_get(http::request<http::string_body> &&request)
{
    const std::string& target {request.target()};
    {//list without pagination
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
    {//rps details (all fist_low_level children)
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

http::response<http::string_body> http_handler::handle_rps_put(http::request<http::string_body> &&request)
{
    const std::string& target {request.target()};
    {//update role_permission
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

http::response<http::string_body> http_handler::handle_rps_post(http::request<http::string_body> &&request)
{
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

http::response<http::string_body> http_handler::handle_rps_delete(http::request<http::string_body> &&request)
{
    const std::string& target {request.target()};
    {//remove role_permission
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

http::response<http::string_body> http_handler::handle_certificates_post(http::request<http::string_body> &&request)
{
    const std::string& target {request.target()};
    {
        boost::regex re {"^/api/v1/u-auth/certificates/user/" + regex_uid_ + "?" + regex_any_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& user_uid {match[1]};
            const std::string& crt_password {match[2]};
        }
    }
    {
        boost::regex re {"^/api/v1/u-auth/certificates/agent/sign-csr$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& csr_binary {request.body()};
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

