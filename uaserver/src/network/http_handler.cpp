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

http::response<http::string_body> http_handler::handle_user(http::request<http::string_body> &&request, const std::string &requester_id)
{
    //verb check
    if((request.method()!=http::verb::get) & (request.method()!=http::verb::put) &
       (request.method()!=http::verb::post) & (request.method()!=http::verb::delete_)){
        return fail(std::move(request),http::status::not_found,"not found");
    }
    switch(request.method()){
    case http::verb::get:
        return handle_user_get(std::move(request),requester_id);
    case http::verb::put:
        return handle_user_put(std::move(request),requester_id);
    case http::verb::post:
        return handle_user_post(std::move(request),requester_id);
    case http::verb::delete_:
        return handle_user_delete(std::move(request),requester_id);
    default:
        return fail(std::move(request),http::status::not_found,"not found");
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
    case http::verb::delete_:
        return handle_authz_manage_delete(std::move(request),requester_id);
    default:
        return fail(std::move(request),http::status::not_found,"not found");
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_rp(http::request<http::string_body> &&request, const std::string &requester_id)
{
    //verb check
    if((request.method()!=http::verb::get) & (request.method()!=http::verb::put) &
       (request.method()!=http::verb::post) & (request.method()!=http::verb::delete_)){
        return fail(std::move(request),http::status::not_found,"not found");
    }
    switch(request.method()){
    case http::verb::get:
        return handle_rp_get(std::move(request),requester_id);
    case http::verb::put:
        return handle_rp_put(std::move(request),requester_id);
    case http::verb::post:
        return handle_rp_post(std::move(request),requester_id);
    case http::verb::delete_:
        return handle_rp_delete(std::move(request),requester_id);
    default:
        return fail(std::move(request),http::status::not_found,"not found");
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_certificate(http::request<http::string_body> &&request, const std::string &requester_id)
{
    if(request.method()==http::verb::post){
        return handle_certificate_post(std::move(request),requester_id);
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_user_get(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    {//users list
        boost::regex re {"^/api/v1/u-auth/users$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            std::string msg {};
            std::string users {};

            const db_status& status_ {dbase_handler_ptr_->user_list_get(users,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,users);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }
    {//user by user_uid
        boost::regex re {"^/api/v1/u-auth/users/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& user_uid {match[1]};
            std::string msg {};
            std::string user {};

            const db_status& status_ {dbase_handler_ptr_->user_info_get(user_uid,user,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,user);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }
    {//user's roles_permissions
        boost::regex re {"^/api/v1/u-auth/users/" + regex_uid_ + "/roles-permissions" + regex_any_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& user_uid {match[1]};
            std::string msg {};
            std::string rps {};

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
                }
            }
            //not need to check limit and offset
            const db_status& status_ {dbase_handler_ptr_->user_rp_get(user_uid,limit,offset,rps,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,rps);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }
    {//users list with limit and/or offset and filter
        boost::regex re {"^/api/v1/u-auth/users" + regex_any_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
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
                }
            }
            //check limit and offset
            if(limit.empty() & offset.empty()){
                 return fail(std::move(request),http::status::not_found,"not found");
            }

            std::string msg {};
            std::string users {};

            const db_status& status_ {dbase_handler_ptr_->user_list_get(users,limit,offset,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,users);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_user_put(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    boost::regex re {"^/api/v1/u-auth/users/" + regex_uid_ + "$"};
    boost::smatch match;
    if(boost::regex_match(target,match,re)){
        std::string msg;
        const std::string& user_uid {match[1]};
        const std::string& body {request.body()};

        const db_status& status_ {dbase_handler_ptr_->user_info_put(user_uid,body,requester_id,msg)};
        switch(status_){
        case db_status::fail:
            return fail(std::move(request),http::status::bad_request,msg);
        case db_status::success:
            return success(std::move(request),http::status::ok,msg);
        case db_status::not_found:
            return fail(std::move(request),http::status::not_found,msg);
        case db_status::unauthorized:
            return fail(std::move(request),http::status::unauthorized,msg);
        default:
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_user_post(http::request<http::string_body> &&request, const std::string &requester_id)
{
    std::string msg;
    const std::string& body {request.body()};

    const db_status& status_ {dbase_handler_ptr_->user_info_post(body,requester_id,msg)};
    switch(status_){
    case db_status::fail:
        return fail(std::move(request),http::status::bad_request,msg);
    case db_status::success:
        return success(std::move(request),http::status::ok,"user created");
    case db_status::not_found:
        return fail(std::move(request),http::status::not_found,msg);
    case db_status::unauthorized:
        return fail(std::move(request),http::status::unauthorized,msg);
    default:
        return fail(std::move(request),http::status::bad_request,msg);
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_user_delete(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    boost::regex re {"^/api/v1/u-auth/users/" + regex_uid_ + "$"};
    boost::smatch match;
    if(!boost::regex_match(target,match,re)){
        return fail(std::move(request),http::status::bad_request,"bad request");
    }
    std::string msg;
    const std::string& user_uid {match[1]};

    const db_status& status_ {dbase_handler_ptr_->user_info_delete(user_uid,requester_id,msg)};
    switch(status_){
    case db_status::fail:
        return fail(std::move(request),http::status::bad_request,msg);
    case db_status::success:
        return success(std::move(request),http::status::no_content,msg);
    case db_status::not_found:
        return fail(std::move(request),http::status::not_found,msg);
    case db_status::unauthorized:
        return fail(std::move(request),http::status::unauthorized,msg);
    default:
        return fail(std::move(request),http::status::bad_request,msg);
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
        std::string msg {};
        bool authorized {false};
        const std::string& user_uid {match[1]};
        const std::string& rp_ident {match[2]};

        const db_status& status_ {dbase_handler_ptr_->authz_check_get(user_uid,rp_ident,authorized,msg)};
        switch(status_){
        case db_status::fail:
            return fail(std::move(request),http::status::bad_request,msg);
        case db_status::success:
            return success(std::move(request),http::status::ok,std::to_string(authorized));
        case db_status::not_found:
            return fail(std::move(request),http::status::not_found,msg);
        case db_status::unauthorized:
            return fail(std::move(request),http::status::unauthorized,msg);
        default:
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_authz_manage_post(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    boost::regex re {"^/api/v1/u-auth/authz/manage/" + regex_uid_ + "/assign/" + regex_uid_ + "$"};
    boost::smatch match;
    if(boost::regex_match(target,match,re)){
        std::string msg {};
        const std::string& requested_user_id {match[1]};
        const std::string& requested_rp_id {match[2]};

        const db_status& status_ {dbase_handler_ptr_->authz_manage_post(requested_user_id,requested_rp_id,requester_id,msg)};
        switch(status_){
        case db_status::fail:
            return fail(std::move(request),http::status::bad_request,msg);
        case db_status::success:
            return success(std::move(request),http::status::ok,msg);
        case db_status::not_found:
            return fail(std::move(request),http::status::not_found,msg);
        case db_status::unauthorized:
            return fail(std::move(request),http::status::unauthorized,msg);
        default:
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_authz_manage_delete(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    boost::regex re {"^/api/v1/u-auth/authz/manage/" + regex_uid_ + "/revoke/" + regex_uid_ + "$"};
    boost::smatch match;
    if(boost::regex_match(target,match,re)){
        std::string msg {};
        const std::string& requested_user_id {match[1]};
        const std::string& requested_rp_id {match[2]};

        const db_status& status_ {dbase_handler_ptr_->authz_manage_delete(requested_user_id,requested_rp_id,requester_id,msg)};
        switch(status_){
        case db_status::fail:
            return fail(std::move(request),http::status::bad_request,msg);
        case db_status::success:
            return success(std::move(request),http::status::ok,msg);
        case db_status::not_found:
            return fail(std::move(request),http::status::not_found,msg);
        case db_status::unauthorized:
            return fail(std::move(request),http::status::unauthorized,msg);
        default:
            return fail(std::move(request),http::status::bad_request,msg);
        }
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_rp_get(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    {//rps list
        boost::regex re {"^/api/v1/u-auth/roles-permissions$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            std::string msg {};
            std::string rps {};

            const db_status& status_ {dbase_handler_ptr_->rp_list_get(rps,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,rps);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }

    {//rps by rp_uid
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& rp_uid {match[1]};
            std::string msg {};
            std::string rp {};

            const db_status& status_ {dbase_handler_ptr_->rp_info_get(rp_uid,rp,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,rp);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }

    {//rps details
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "/detail$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& rp_uid {match[1]};
            std::string msg {};
            std::string rp_detail {};

            const db_status& status_ {dbase_handler_ptr_->rp_rp_detail_get(rp_uid,rp_detail,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,rp_detail);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }

    {//all users for rps by rp_uid
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "/associated-users$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& rp_uid {match[1]};
            std::string msg {};
            std::string users {};

            const db_status& status_ {dbase_handler_ptr_->rp_user_get(rp_uid,users,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,users);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }

    {//all users for rps by rp_uid with limit and/or offset
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "/associated-users" + regex_any_ + "$"};
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
                }
            }
            //check limit and offset
            if(limit.empty() & offset.empty()){
                 return fail(std::move(request),http::status::not_found,"not found");
            }

            std::string msg {};
            std::string users {};

            const db_status& status_ {dbase_handler_ptr_->rp_user_get(rp_uid,users,limit,offset,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,users);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }

    {//rp list with limit and/or offset
        boost::regex re {"^/api/v1/u-auth/roles-permissions" + regex_any_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
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
                }
            }
            //check limit and offset
            if(limit.empty() & offset.empty()){
                 return fail(std::move(request),http::status::not_found,"not found");
            }

            std::string msg {};
            std::string rps {};
            const db_status& status_ {dbase_handler_ptr_->rp_list_get(rps,limit,offset,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,rps);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }
    return fail(std::move(request),http::status::bad_request,"bad request");
}

http::response<http::string_body> http_handler::handle_rp_put(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    {//update role_permission
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            std::string msg;
            const std::string& rp_uid {match[1]};
            const std::string& body {request.body()};

            const db_status& status_ {dbase_handler_ptr_->rp_info_put(rp_uid,body,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,msg);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }
    {//add role_permission relationship
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "/add-child/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            std::string msg;
            const std::string& parent_uid {match[1]};
            const std::string& child_uid {match[2]};

            const db_status& status_ {dbase_handler_ptr_->rp_child_put(parent_uid,child_uid,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,msg);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_rp_post(http::request<http::string_body> &&request, const std::string &requester_id)
{
    std::string msg;
    const std::string& body {request.body()};

    const db_status& status_ {dbase_handler_ptr_->rp_info_post(body,requester_id,msg)};
    switch(status_){
    case db_status::fail:
        return fail(std::move(request),http::status::bad_request,msg);
    case db_status::success:
        return success(std::move(request),http::status::ok,msg);
    case db_status::not_found:
        return fail(std::move(request),http::status::not_found,msg);
    case db_status::unauthorized:
        return fail(std::move(request),http::status::unauthorized,msg);
    case db_status::conflict:
        return fail(std::move(request),http::status::conflict,msg);
    default:
        return fail(std::move(request),http::status::bad_request,msg);
    }
}

http::response<http::string_body> http_handler::handle_rp_delete(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    {//remove role_permission
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            std::string msg;
            const std::string& rp_uid {match[1]};

            const db_status& status_ {dbase_handler_ptr_->rp_info_delete(rp_uid,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::no_content,msg);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            case db_status::unprocessable_entity:
                return fail(std::move(request),http::status::unprocessable_entity,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }
    {//remove role_permission relationship
        boost::regex re {"^/api/v1/u-auth/roles-permissions/" + regex_uid_ + "/remove-child/" + regex_uid_ + "$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            std::string msg;
            const std::string& parent_uid {match[1]};
            const std::string& child_uid {match[2]};

            const db_status& status_ {dbase_handler_ptr_->rp_child_delete(parent_uid,child_uid,requester_id,msg)};
            switch(status_){
            case db_status::fail:
                return fail(std::move(request),http::status::bad_request,msg);
            case db_status::success:
                return success(std::move(request),http::status::ok,msg);
            case db_status::not_found:
                return fail(std::move(request),http::status::not_found,msg);
            case db_status::unauthorized:
                return fail(std::move(request),http::status::unauthorized,msg);
            default:
                return fail(std::move(request),http::status::bad_request,msg);
            }
        }
    }
    return fail(std::move(request),http::status::not_found,"not found");
}

http::response<http::string_body> http_handler::handle_certificate_post(http::request<http::string_body> &&request, const std::string &requester_id)
{
    const std::string& target {request.target()};
    {//handle user certificate
        {//check if authorized
            std::string msg {};
            bool authorized {false};
            const std::string& rp_name {"user_certificate"};

            const db_status& status_ {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,authorized,msg)};
            boost::ignore_unused(status_);
            if(!authorized){
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
                const db_status& status_ {dbase_handler_ptr_->user_info_get(user_id,user,requester_id,msg)};
                if(status_!=db_status::success){
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
            const std::string& pub_path  {params_.at("UA_SIGNING_CA_CRT_PATH").as_string().c_str()};
            const std::string& pr_path   {params_.at("UA_SIGNING_CA_KEY_PATH").as_string().c_str()};
            const std::string& pr_pass   {params_.at("UA_SIGNING_CA_KEY_PASS").as_string().c_str()};

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
            bool authorized {false};
            const std::string& rp_name {"agent_certificate"};

            const db_status& status_ {dbase_handler_ptr_->authz_check_get(requester_id,rp_name,authorized,msg)};
            boost::ignore_unused(status_);
            if(!authorized){
                return fail(std::move(request),http::status::unauthorized,"unauthorized");
            }
        }
        boost::regex re {"^/api/v1/u-auth/certificates/agent/sign-csr$"};
        boost::smatch match;
        if(boost::regex_match(target,match,re)){
            const std::string& content {request.body()};
            const std::vector<char>& x509_REQ_content {content.begin(),content.end()};
            const std::string& pub_path {params_.at("UA_SIGNING_CA_CRT_PATH").as_string().c_str()};
            const std::string& pr_path  {params_.at("UA_SIGNING_CA_KEY_PATH").as_string().c_str()};
            const std::string& pr_pass  {params_.at("UA_SIGNING_CA_KEY_PASS").as_string().c_str()};

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

http_handler::http_handler(const boost::json::object &params, uc_status status, std::shared_ptr<spdlog::logger> logger_ptr)
    :params_{params},status_{status},logger_ptr_{logger_ptr}
{
    {//init dbase_handler
        dbase_handler_ptr_.reset(new dbase_handler{params_,logger_ptr});
    }
}

