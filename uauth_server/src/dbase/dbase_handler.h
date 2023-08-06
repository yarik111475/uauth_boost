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

enum status{
    fail,
    success,
    not_found,
    unauthorized
};

class dbase_handler
{
private:
    boost::asio::io_context io_;
    boost::json::object params_ {};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};
    static bool is_initiated_;


    std::string time_with_timezone();
    PGconn* open_connection(std::string& msg);
    bool init_tables(PGconn* conn_ptr, std::string &msg);
    bool init_default_rps(PGconn* conn_ptr, std::string &msg);

    //Check if rp exists
    bool is_rp_exists(PGconn* conn_ptr,const std::string& rp_uid,std::string& msg);
    //Check if user exists
    bool is_user_exists(PGconn* conn_ptr,const std::string& user_uid,std::string& msg);
    //Check if user authorized
    bool is_authorized(PGconn* conn_ptr, const std::string& user_uid, const std::string& rp_ident);
    //Get total urp
    int urp_total_get(PGconn* conn_ptr);
    //Get total rps
    int rps_total_get(PGconn* conn_ptr);
    //Get total users
    int users_total_get(PGconn* conn_ptr);
    //Get UAuthAmin rp_uid
    std::string uath_admin_rp_uid_get(PGconn* conn_ptr);

    void rp_uid_recursive_get(PGconn* conn_ptr, std::vector<std::string> &rp_uids);
    void rp_children_get(PGconn* conn_ptr,const std::string& rp_uid,boost::json::array& rp_objs);
    void rp_uids_by_rp_names_get(PGconn* conn_ptr,const std::vector<std::string>& rp_names,std::vector<std::string>& rp_uids);

public:
    explicit dbase_handler(const boost::json::object& params,std::shared_ptr<spdlog::logger> logger_ptr);
    ~dbase_handler()=default;

    //Init database
    bool init_database(std::string& msg);
    //List Of Users
    status users_list_get(std::string& users,const std::string& requester_id,std::string& msg);
    //List Of Users with limit and/or offset and filter
    status users_list_get(std::string& users,const std::string& limit,const std::string& offset,
                        const std::string& first_name,const std::string& last_name,
                        const std::string& email,const std::string& is_blocked,const std::string& requester_id,std::string& msg);
    //Get User Info
    status users_info_get(const std::string& user_uid, std::string &user,const std::string& requester_id,std::string& msg);
    //Get User Assigned Roles And Permissions
    status users_rps_get(const std::string& user_uid,std::string& rps,const std::string& requester_id,std::string& msg);
    //Get User Assigned Roles And Permissions with limit and/or offset
    status users_rps_get(const std::string& user_uid,std::string& rps,
                       const std::string& limit,const std::string& offset,const std::string& requester_id,std::string& msg);
    //Update User
    status users_info_put(const std::string& user_uid,const std::string& user,const std::string& requester_id,std::string& msg);
    //Create User
    status users_info_post(const std::string& user,const std::string& requester_id,std::string& msg);
    //Delete User
    status users_info_delete(const std::string& user_uid,const std::string& requester_id,std::string& msg);

    //List Of Roles And Permissions
    status rps_list_get(std::string& rps,const std::string& requester_id,std::string& msg);
    //List Of Roles And Permissions with limit and/or offset and filter
    status rps_list_get(std::string& rps,const std::string& limit,
                      const std::string offset,const std::string& name,
                      const std::string& type,const std::string& description,const std::string& requester_id,std::string& msg);
    //Get Permission Or Role
    status rps_info_get(const std::string& rp_uid,std::string& rp,const std::string& requester_id,std::string& msg);
    //Get Associated Users
    status rps_users_get(const std::string& rp_uid,std::string& users,const std::string& requester_id,std::string& msg);
    //Get Associated Users with limit and/or offset
    status rps_users_get(const std::string& rp_uid,std::string& users,const
                       std::string& limit,const std::string& offset,const std::string& requester_id,std::string& msg);
    //Get Permission Or Role Detail
    status rps_rp_detail_get(const std::string& rp_uid,std::string& rp,const std::string& requester_id,std::string& msg);
    //Create Permission Or Role
    status rps_info_post(const std::string& rp,const std::string& requester_id,std::string& msg);
    //Update Permission Or Role
    status rps_info_put(const std::string& rp_uid,const std::string& rp,const std::string& requester_id,std::string& msg);
    //Delete Permission Or Role
    status rps_info_delete(const std::string& rp_uid, const std::string &requester_id, std::string& msg);
    //Add Child To Role
    status rps_child_put(const std::string& parent_uid,const std::string& child_uid,const std::string& requester_id,std::string& msg);
    //Remove Child From Role
    status rps_child_delete(const std::string& parent_uid,const std::string& child_uid,const std::string& requester_id,std::string& msg);

    //Check That User Authorized To Role Or Permission
    status authz_check_get(const std::string& user_uid, const std::string& rp_ident, bool& authorized, std::string& msg);
    //Assign Role Or Permission To User
    status authz_manage_post(const std::string& requested_user_uid, const std::string& requested_rp_uid,const std::string& requester_id,std::string& msg);
    //Revoke Role Or Permission From User
    status authz_manage_delete(const std::string& requested_user_uid,const std::string& requested_rp_uid,const std::string& requester_id,std::string& msg);
};

#endif // DBASE_HANDLER_H
