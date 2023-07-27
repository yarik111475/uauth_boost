#ifndef DBASE_HANDLER_H
#define DBASE_HANDLER_H

#include <string>
#include <memory>
#include <boost/json.hpp>
#include <boost/asio.hpp>

#include "libpq-fe.h"
#include "spdlog/spdlog.h"

namespace spdlog{
    class logger;
}

class dbase_handler
{
private:
    boost::asio::io_context io_;
    boost::json::object params_ {};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};

    std::string time_with_timezone();
    PGconn* open_connection(std::string& msg);
    bool init_tables(PGconn* conn_ptr, std::string &msg);

    bool is_rp_exists(PGconn* conn_ptr,const std::string& rp_uid,std::string& msg);
    bool is_user_exists(PGconn* conn_ptr,const std::string& user_uid,std::string& msg);

    int urp_total_get(PGconn* conn_ptr);
    int rps_total_get(PGconn* conn_ptr);
    int users_total_get(PGconn* conn_ptr);

    void rp_uid_recursive_get(PGconn* conn_ptr, const std::string& rp_uid, std::vector<std::string> &rp_uids);
    void rp_children_get(PGconn* conn_ptr,const std::string& rp_uid,boost::json::array& rp_objs);
    void rp_uids_by_rp_names_get(PGconn* conn_ptr,const std::vector<std::string>& rp_names,std::vector<std::string>& rp_uids);

public:
    explicit dbase_handler(const boost::json::object& params,std::shared_ptr<spdlog::logger> logger_ptr);
    ~dbase_handler()=default;

    //List Of Users
    bool users_list_get(std::string& users,std::string& msg);
    //List Of Users with limit and/or offset and filter
    bool users_list_get(std::string& users,const std::string& limit,const std::string& offset,
                        const std::string& first_name,const std::string& last_name,
                        const std::string& email,const std::string& is_blocked,std::string& msg);
    //Get User Info
    bool users_info_get(const std::string& user_uid, std::string &user, std::string& msg);
    //Get User Assigned Roles And Permissions
    bool users_rps_get(const std::string& user_uid,std::string& rps,std::string& msg);
    //Get User Assigned Roles And Permissions with limit and/or offset
    bool users_rps_get(const std::string& user_uid,std::string& rps,
                       const std::string& limit,const std::string& offset,std::string& msg);
    //Update User
    bool users_info_put(const std::string& user_uid,const std::string& user,std::string& msg);
    //Create User
    bool users_info_post(const std::string& user,std::string& msg);
    //Delete User
    bool users_info_delete(const std::string& user_uid,std::string& msg);

    //List Of Roles And Permissions
    bool rps_list_get(std::string& rps,std::string& msg);
    //List Of Roles And Permissions with limit and/or offset and filter
    bool rps_list_get(std::string& rps,const std::string& limit,
                      const std::string offset,const std::string& name,
                      const std::string& type,const std::string& description,std::string& msg);
    //Get Permission Or Role
    bool rps_info_get(const std::string& rp_uid,std::string& rp,std::string& msg);
    //Get Associated Users
    bool rps_users_get(const std::string& rp_uid,std::string& users,std::string& msg);
    //Get Associated Users with limit and/or offset
    bool rps_users_get(const std::string& rp_uid,std::string& users,const
                       std::string& limit,const std::string& offset,std::string& msg);
    //Get Permission Or Role Detail
    bool rps_rp_detail_get(const std::string& rp_uid,std::string& rp,std::string& msg);
    //Create Permission Or Role
    bool rps_info_post(const std::string& rp,std::string& msg);
    //Update Permission Or Role
    bool rps_info_put(const std::string& rp_uid,const std::string& rp,std::string& msg);
    //Delete Permission Or Role
    bool rps_info_delete(const std::string& rp_uid,std::string& msg);
    //Add Child To Role
    bool rps_child_put(const std::string& parent_uid,const std::string& child_uid,std::string& msg);
    //Remove Child From Role
    bool rps_child_delete(const std::string& parent_uid,const std::string& child_uid,std::string& msg);

    //Check That User Authorized To Role Or Permission
    bool authz_check_get(const std::string& user_uid,const std::string& rp_ident,std::string& msg);
    //Assign Role Or Permission To User
    bool authz_manage_post(const std::string& requested_user_uid, const std::string& requested_rp_uid,std::string& msg);
    //Revoke Role Or Permission From User
    bool authz_manage_delete(const std::string& requested_user_uid,const std::string& requested_rp_uid,std::string& msg);
};

#endif // DBASE_HANDLER_H
