#include "dbase_handler.h"

#include <vector>
#include <boost/json.hpp>
#include <boost/regex.hpp>
#include <boost/format.hpp>
#include <boost/date_time.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/algorithm/string.hpp>

//get date_time with timezone as std::string
std::string dbase_handler::time_with_timezone()
{
    const boost::posix_time::ptime& local_time {boost::posix_time::microsec_clock::local_time()};
    const boost::posix_time::ptime& universal_time {boost::posix_time::microsec_clock::universal_time()};
    const boost::posix_time::time_duration& difference {local_time-universal_time};
    const double& hours_delta {std::round(difference.hours() + std::round(difference.minutes())/60)};

    const std::string& iso_ext_time {boost::posix_time::to_iso_extended_string(local_time)};
    const std::string& time {(boost::format("%s+%02d:00")
                                      % iso_ext_time
                                      % hours_delta).str()};
    return time;
}

//open PGConnection
PGconn *dbase_handler::open_connection(std::string &msg)
{
    PGconn* conn_ptr {NULL};
    const std::string& db_host {params_.at("db_host").as_string().c_str()};
    const std::string& db_port {params_.at("db_port").as_string().c_str()};
    const std::string& db_user {params_.at("db_user").as_string().c_str()};
    const std::string& db_pass {params_.at("db_pass").as_string().c_str()};
    const std::string& db_name {params_.at("db_name").as_string().c_str()};

    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver r {io_};
    const auto& ep_list {r.resolve(db_host,db_port,ec)};
    if(ec){
        msg=ec.message();
        return nullptr;
    }
    boost::asio::ip::tcp::endpoint ep {*ep_list.begin()};
    std::string conninfo {(boost::format("postgresql://%s:%s@%s:%d/%s?connect_timeout=10")
        % db_user
        % db_pass
        % ep.address().to_string()
        % ep.port()
        % db_name).str()};

    conn_ptr=PQconnectdb(conninfo.c_str());
    if(PQstatus(conn_ptr)!=CONNECTION_OK){
        msg=std::string {PQerrorMessage(conn_ptr)};
        return nullptr;
    }
    return conn_ptr;
}

//init database and tables if empty
bool dbase_handler::init_tables(PGconn *conn_ptr,std::string& msg)
{
    PGresult* res_ptr {NULL};
    {//create database
    }
    {//drop type if exists 'rolepermissiontype'
        const std::string& command {"DROP TYPE IF EXISTS rolepermissiontype_new"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            //return false;
        }
    }
    {//create type 'rolepermissiontype'
        const std::string& command {"CREATE TYPE rolepermissiontype_new AS ENUM ('role','permission')"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            //return false;
        }
    }
    {//create table 'users'
        const std::string& command {"CREATE TABLE IF NOT EXISTS users_new "
                                    "(id uuid PRIMARY KEY NOT NULL, created_at timestamptz NOT NULL, "
                                    "updated_at timestamptz NOT NULL, first_name varchar(20) NULL, "
                                    "last_name varchar(20) NULL, email varchar(60) NULL, is_blocked boolean NOT NULL)"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }
    }
    {//create table 'roles_permissions'
        const std::string& command {"CREATE TABLE IF NOT EXISTS roles_permissions_new "
                                    "(id uuid PRIMARY KEY NOT NULL, name varchar(50) NULL, "
                                    "description varchar NULL, type rolepermissiontype_new NULL)"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }
    }
    {//create table 'users_roles_permissions'
        const std::string& command {"CREATE TABLE IF NOT EXISTS users_roles_permissions_new "
                                    "(created_at timestamptz NOT NULL, user_id uuid NOT NULL, role_permission_id uuid NOT NULL)"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }
    }
    {//create table 'roles_permissions_relationship'
        const std::string& command {"CREATE TABLE IF NOT EXISTS roles_permissions_relationship_new "
                                    "(created_at timestamptz NOT NULL, parent_id uuid NOT NULL, child_id uuid NOT NULL)"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }
    }
    return true;
}

bool dbase_handler::is_rp_exists(PGconn *conn_ptr, const std::string &rp_uid, std::string &msg)
{
    PGresult* res_ptr=PQexec(conn_ptr,"SELECT * FROM roles_permissions");
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        msg="role-permission not found";
        return false;
    }

    PQclear(res_ptr);
    return true;
}

bool dbase_handler::is_user_exists(PGconn *conn_ptr, const std::string &user_uid, std::string &msg)
{
    const char* param_values[] {user_uid.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM users WHERE id=$1",
        1,NULL,param_values,NULL,NULL,0);

    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        msg="user not found";
        return false;
    }

    PQclear(res_ptr);
    return true;
}

//recursive get all low_level rp_uids by top_level rp_uid
void dbase_handler::rp_uid_recursive_get(PGconn *conn_ptr, const std::string &rp_uid, std::vector<std::string>& rp_uids)
{
    PGresult* res_ptr {NULL};
    const char* param_values[]{rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,"SELECT child_id from roles_permissions_relationship WHERE parent_id=$1",
                         1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        PQclear(res_ptr);
        return;
    }
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        return;
    }
    else{
        const std::string& child_rp_uid  {PQgetvalue(res_ptr,0,0)};
        rp_uids.push_back(child_rp_uid);
        rp_uid_recursive_get(conn_ptr,child_rp_uid,rp_uids);
    }
}

//get all first_low_level rp_objects by top_level rp_uid
void dbase_handler::rp_children_get(PGconn *conn_ptr, const std::string &rp_uid, boost::json::array &rp_objs)
{
    PGresult* res_ptr {NULL};
    const char* param_values[]{rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,"SELECT child_id from roles_permissions_relationship WHERE parent_id=$1",
                         1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        PQclear(res_ptr);
        return;
    }
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        return;
    }
    else{
        for(int r=0;r<rows;++r){
            const std::string rp_uid {PQgetvalue(res_ptr,r,0)};
            const char* param_values[] {rp_uid.c_str()};
            PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM roles_permissions WHERE id=$1",
                                           1,NULL,param_values,NULL,NULL,0);

            if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
                PQclear(res_ptr);
                continue;
            }

            const int& rows {PQntuples(res_ptr)};
            const int& columns {PQnfields(res_ptr)};
            boost::json::object rp_ {};

            for(int r=0;r < rows;++r){
                boost::json::object rp_ {};
                for(int c=0;c < columns;++c){
                    const std::string& key {PQfname(res_ptr,c)};
                    const std::string& value {PQgetvalue(res_ptr,r,c)};
                    rp_.emplace(key,value);
                }
                rp_objs.push_back(rp_);
            }
            PQclear(res_ptr);
        }
    }
}

//get all rp_uids by rp_names
void dbase_handler::rp_uids_by_rp_names_get(PGconn *conn_ptr, const std::vector<std::string> &rp_names, std::vector<std::string> &rp_uids)
{
    PGresult* res_ptr {NULL};
    for(const std::string& rp_name: rp_names){
        const char* param_values[]{rp_name.c_str()};
        res_ptr=PQexecParams(conn_ptr,"SELECT id from roles_permissions WHERE name=$1",
                             1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            PQclear(res_ptr);
            continue;
        }
        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            continue;
        }
        for(int r=0;r<rows;++r){
            const std::string& rp_uid {PQgetvalue(res_ptr,r,0)};
            rp_uids.push_back(rp_uid);
        }
        PQclear(res_ptr);
    }
}

dbase_handler::dbase_handler(const boost::json::object &params, std::shared_ptr<spdlog::logger> logger_ptr)
    :io_{},params_{params},logger_ptr_{logger_ptr}
{
}

//List Of Users
bool dbase_handler::users_list_get(std::string &users, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }

    PGresult* res_ptr=PQexec(conn_ptr,"SELECT * FROM users");
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    const int& columns {PQnfields(res_ptr)};

    boost::json::array users_ {};
    for(int r=0;r < rows;++r){
        boost::json::object user_ {};
        for(int c=0;c < columns;++c){
            const std::string& key {PQfname(res_ptr,c)};
            const std::string& value {PQgetvalue(res_ptr,r,c)};
            user_.emplace(key,value);
        }
        users_.push_back(user_);
    }
    PQclear(res_ptr);
    PQfinish(conn_ptr);

    users=boost::json::serialize(users_);
    return true;
}

//List Of Users with limit and/or offset
bool dbase_handler::users_list_get(std::string& users,const std::string& limit,const std::string& offset,std::string& msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    std::string command {"SELECT * FROM users"};
    if(!limit.empty()){
        command +=" LIMIT " + limit;
    }
    if(!offset.empty()){
    command +=" OFFSET " + offset;
    }
    PGresult* res_ptr=PQexec(conn_ptr,command.c_str());
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    const int& columns {PQnfields(res_ptr)};

    boost::json::array users_ {};
    for(int r=0;r < rows;++r){
        boost::json::object user_ {};
        for(int c=0;c < columns;++c){
            const std::string& key {PQfname(res_ptr,c)};
            const std::string& value {PQgetvalue(res_ptr,r,c)};
            user_.emplace(key,value);
        }
        users_.push_back(user_);
    }
    PQclear(res_ptr);
    PQfinish(conn_ptr);

    users=boost::json::serialize(users_);
    return true;
}

//Get User Info
bool dbase_handler::users_info_get(const std::string &user_uid, std::string &user, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    const char* param_values[] {user_uid.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM users WHERE id=$1",
        1,NULL,param_values,NULL,NULL,0);

    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }

    const int& columns {PQnfields(res_ptr)};
    boost::json::object user_ {};

    for(int c=0;c < columns;++c){
        const std::string& key {PQfname(res_ptr,c)};
        const std::string& value {PQgetvalue(res_ptr,0,c)};
        user_.emplace(key,value);
    }
    PQclear(res_ptr);
    PQfinish(conn_ptr);

    user=boost::json::serialize(user_);
    return true;
}

//Get User Assigned Roles And Permissions
bool dbase_handler::users_rps_get(const std::string &user_uid, std::string &rps, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }

    const char* param_values[] {user_uid.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT role_permission_id FROM users_roles_permissions WHERE user_id=$1",
                                   1,NULL,param_values,NULL,NULL,0);

    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }

    boost::json::array rps_ {};
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    else{
        std::vector<std::string> rp_ids {};
        for(int r=0;r<rows;++r){
            const std::string& rp_id {PQgetvalue(res_ptr,r,0)};
            rp_ids.push_back(rp_id);
        }
        for(const std::string& rp_id: rp_ids){
            const char* param_values[] {rp_id.c_str()};
            PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM roles_permissions WHERE id=$1",
                                           1,NULL,param_values,NULL,NULL,0);

            if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
                PQclear(res_ptr);
                continue;
            }
            const int& columns {PQnfields(res_ptr)};
            boost::json::object rp_ {};

            for(int c=0;c < columns;++c){
                const std::string& key {PQfname(res_ptr,c)};
                const std::string& value {PQgetvalue(res_ptr,0,c)};
                rp_.emplace(key,value);
            }
            rps_.push_back(rp_);
            PQclear(res_ptr);
        }
    }
    PQfinish(conn_ptr);

    rps=boost::json::serialize(rps_);
    return true;
}

//Update User
bool dbase_handler::users_info_put(const std::string &user_uid, const std::string &user, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    const boost::json::value& v {boost::json::parse(user)};
    const boost::json::object& user_obj {v.as_object()};;
    const std::string& first_name {user_obj.at("first_name").as_string().c_str()};
    const std::string& last_name {user_obj.at("last_name").as_string().c_str()};
    const std::string& email {user_obj.at("email").as_string().c_str()};
    const std::string& is_blocked {std::to_string(user_obj.at("is_blocked").as_bool())};

    const std::string& updated_at {time_with_timezone()};

    {//update user
        const char* param_values[] {first_name.c_str(),last_name.c_str(),email.c_str(),is_blocked.c_str(),updated_at.c_str(),user_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"UPDATE users SET first_name=$1,last_name=$2,email=$3,is_blocked=$4,updated_at=$5 WHERE id=$6",
                                       6,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
        PQclear(res_ptr);
    }

    {//get updated user back
        const char* param_values[] {user_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM users WHERE id=$1",
                                       1,NULL,param_values,NULL,NULL,0);

        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }

        const int& columns {PQnfields(res_ptr)};
        boost::json::object user_ {};

        for(int c=0;c < columns;++c){
            const std::string& key {PQfname(res_ptr,c)};
            const std::string& value {PQgetvalue(res_ptr,0,c)};
            user_.emplace(key,value);
        }
        msg=boost::json::serialize(user_);
        PQclear(res_ptr);
    }
    return true;
}

//Create User
bool dbase_handler::users_info_post(const std::string &user, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    const boost::json::value& v {boost::json::parse(user)};
    const boost::json::object& user_obj {v.as_object()};
    const std::string& first_name {user_obj.at("first_name").as_string().c_str()};
    const std::string& last_name {user_obj.at("last_name").as_string().c_str()};
    const std::string& email {user_obj.at("email").as_string().c_str()};

    const boost::uuids::uuid& uuid_ {boost::uuids::random_generator()()};
    const std::string& uuid {boost::uuids::to_string(uuid_)};

    const std::string& created_at {time_with_timezone()};
    const std::string& updated_at {time_with_timezone()};

    const std::string& is_blocked {std::to_string(false)};

    const char* param_values[] {uuid.c_str(),first_name.c_str(),last_name.c_str(),email.c_str(),created_at.c_str(),updated_at.c_str(),is_blocked.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"INSERT INTO users (id,first_name,last_name,email,created_at,updated_at,is_blocked) VALUES($1,$2,$3,$4,$5,$6,$7)",
                                   7,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    return true;
}

//Delete User
bool dbase_handler::users_info_delete(const std::string &user_uid, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    const char* param_values[] {user_uid.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"DELETE FROM users WHERE id=$1",
                                   1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    return true;
}

//List Of Roles And Permissions
bool dbase_handler::rps_list_get(std::string &rps, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }

    PGresult* res_ptr=PQexec(conn_ptr,"SELECT * FROM roles_permissions");
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    const int& columns {PQnfields(res_ptr)};
    boost::json::array rps_ {};

    for(int r=0;r < rows;++r){
        boost::json::object rp_ {};
        for(int c=0;c < columns;++c){
            const std::string& key {PQfname(res_ptr,c)};
            const std::string& value {PQgetvalue(res_ptr,r,c)};
            rp_.emplace(key,value);
        }
        rps_.push_back(rp_);
    }
    PQclear(res_ptr);
    PQfinish(conn_ptr);
    rps=boost::json::serialize(rps_);
    return true;
}

//List Of Roles And Permissions with limit and/or offset
bool dbase_handler::rps_list_get(std::string &rps, const std::string &limit, const std::string offset, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    std::string command {"SELECT * FROM roles_permissions"};
    if(!limit.empty()){
        command +=" LIMIT " + limit;
    }
    if(!offset.empty()){
        command +=" OFFSET " + offset;
    }

    PGresult* res_ptr=PQexec(conn_ptr,command.c_str());
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    const int& columns {PQnfields(res_ptr)};
    boost::json::array rps_ {};

    for(int r=0;r < rows;++r){
        boost::json::object rp_ {};
        for(int c=0;c < columns;++c){
            const std::string& key {PQfname(res_ptr,c)};
            const std::string& value {PQgetvalue(res_ptr,r,c)};
            rp_.emplace(key,value);
        }
        rps_.push_back(rp_);
    }
    PQclear(res_ptr);
    PQfinish(conn_ptr);
    rps=boost::json::serialize(rps_);
    return true;
}

//Get Permission Or Role
bool dbase_handler::rps_info_get(const std::string &rp_uid, std::string &rp, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    const char* param_values[] {rp_uid.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM roles_permissions WHERE id=$1",
                                   1,NULL,param_values,NULL,NULL,0);

    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    const int& columns {PQnfields(res_ptr)};
    boost::json::object rp_ {};

    for(int c=0;c < columns;++c){
        const std::string& key {PQfname(res_ptr,c)};
        const std::string& value {PQgetvalue(res_ptr,0,c)};
        rp_.emplace(key,value);
    }
    PQclear(res_ptr);
    PQfinish(conn_ptr);

    rp=boost::json::serialize(rp_);
    return true;
}

//Get Associated Users
bool dbase_handler::rps_users_get(const std::string &rp_uid, std::string &users, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }

    const char* param_values[] {rp_uid.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT user_id FROM users_roles_permissions WHERE role_permission_id=$1",
                                   1,NULL, param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }

    boost::json::array users_ {};
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        users=boost::json::serialize(users_);
        return true;
    }
    else{
        std::vector<std::string> user_ids {};
        for(int r=0;r<rows;++r){
            const std::string& user_id {PQgetvalue(res_ptr,r,0)};
            user_ids.push_back(user_id);
        }

        for(const std::string& user_id: user_ids){
            const char* param_values[] {user_id.c_str()};
            PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM users WHERE id=$1",
                1,NULL,param_values,NULL,NULL,0);

            if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
                PQclear(res_ptr);
                continue;
            }

            const int& columns {PQnfields(res_ptr)};
            boost::json::object user_ {};

            for(int c=0;c < columns;++c){
                const std::string& key {PQfname(res_ptr,c)};
                const std::string& value {PQgetvalue(res_ptr,0,c)};
                user_.emplace(key,value);
            }
            users_.push_back(user_);
            PQclear(res_ptr);
        }
    }
    PQfinish(conn_ptr);

    users=boost::json::serialize(users_);
    return true;
}

//Get Permission Or Role Detail
bool dbase_handler::rps_rp_detail_get(const std::string &rp_uid, std::string &rp, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }

    const char* param_values[] {rp_uid.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM roles_permissions WHERE id=$1",
                                   1,NULL,param_values,NULL,NULL,0);

    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    const int& columns {PQnfields(res_ptr)};
    boost::json::object rp_ {};

    for(int c=0;c < columns;++c){
        const std::string& key {PQfname(res_ptr,c)};
        const std::string& value {PQgetvalue(res_ptr,0,c)};
        rp_.emplace(key,value);
    }
    PQclear(res_ptr);

    //get all first_level children for rp
    boost::json::array children {};
    rp_children_get(conn_ptr,rp_.at("id").as_string().c_str(),children);
    rp_.emplace("children",children);
    PQfinish(conn_ptr);

    rp=boost::json::serialize(rp_);
    return true;
}

//Create Permission Or Role
bool dbase_handler::rps_info_post(const std::string &rp, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    const boost::json::value& v {boost::json::parse(rp)};
    const boost::json::object& rp_obj {v.as_object()};
    const std::string& name {rp_obj.at("name").as_string().c_str()};
    const std::string& type {rp_obj.at("type").as_string().c_str()};
    const std::string& description {rp_obj.at("description").as_string().c_str()};

    const boost::uuids::uuid& uuid_ {boost::uuids::random_generator()()};
    const std::string& uuid {boost::uuids::to_string(uuid_)};

    const char* param_values[] {uuid.c_str(),name.c_str(),type.c_str(),description.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"INSERT INTO roles_permissions (id,name,type,description) VALUES($1,$2,$3,$4)",
                                   4,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    return true;
}

//Update Permission Or Role
bool dbase_handler::rps_info_put(const std::string &rp_uid, const std::string &rp, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    const boost::json::value& v {boost::json::parse(rp)};
    const boost::json::object& rp_obj {v.as_object()};;
    const std::string& name {rp_obj.at("name").as_string().c_str()};
    const std::string& type {rp_obj.at("type").as_string().c_str()};
    const std::string& description {rp_obj.at("description").as_string().c_str()};

    {//update user
        const char* param_values[] {name.c_str(),type.c_str(),description.c_str(),rp_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"UPDATE roles_permissions SET name=$1,type=$2,description=$3 WHERE id=$4",
                                       4,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
        PQclear(res_ptr);
    }

    {//get updated user back
        const char* param_values[] {rp_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM roles_permissions WHERE id=$1",
                                       1,NULL,param_values,NULL,NULL,0);

        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }

        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};

        for(int c=0;c < columns;++c){
            const std::string& key {PQfname(res_ptr,c)};
            const std::string& value {PQgetvalue(res_ptr,0,c)};
            rp_.emplace(key,value);
        }
        msg=boost::json::serialize(rp_);
        PQclear(res_ptr);
    }
    return true;
}

//Delete Permission Or Role
bool dbase_handler::rps_info_delete(const std::string &rp_uid, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    const char* param_values[] {rp_uid.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"DELETE FROM roles_permissions WHERE id=$1",
                                   1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
    }
    return true;
}

//Add Child To Role
bool dbase_handler::rps_child_put(const std::string &parent_uid, const std::string &child_uid, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    {//check
        if(!is_rp_exists(conn_ptr,parent_uid,msg) || !is_rp_exists(conn_ptr,child_uid,msg)){
            PQfinish(conn_ptr);
            return false;
        }
    }
    {//create relationship
        const std::string& created_at {time_with_timezone()};
        const char* param_values[] {created_at.c_str(),parent_uid.c_str(),child_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"INSERT INTO roles_permissions_relationship (created_at,parent_id,child_id) VALUES($1,$2,$3)",
                                       3,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
    }
    {//send rp with all children back
        const char* param_values[] {parent_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM roles_permissions WHERE id=$1",
                                       1,NULL,param_values,NULL,NULL,0);

        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }

        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};

        for(int c=0;c < columns;++c){
            const std::string& key {PQfname(res_ptr,c)};
            const std::string& value {PQgetvalue(res_ptr,0,c)};
            rp_.emplace(key,value);
        }
        PQclear(res_ptr);

        //get all first_level children for rp
        boost::json::array children {};
        rp_children_get(conn_ptr,rp_.at("id").as_string().c_str(),children);
        rp_.emplace("children",children);
        PQfinish(conn_ptr);

        msg=boost::json::serialize(rp_);
        return true;
    }
    return false;
}

//Remove Child From Role
bool dbase_handler::rps_child_delete(const std::string &parent_uid, const std::string &child_uid, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    {//check
        if(!is_rp_exists(conn_ptr,parent_uid,msg) || !is_rp_exists(conn_ptr,child_uid,msg)){
            PQfinish(conn_ptr);
            return false;
        }
    }
    {//delete relationship
        const char* param_values[] {parent_uid.c_str(),child_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"DELETE FROM roles_permissions_relationship WHERE parent_id=$1 AND child_id=$2",
                                       2,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
    }
    {//send rp with all children back
        const char* param_values[] {parent_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM roles_permissions WHERE id=$1",
                                       1,NULL,param_values,NULL,NULL,0);

        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }

        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};

        for(int c=0;c < columns;++c){
            const std::string& key {PQfname(res_ptr,c)};
            const std::string& value {PQgetvalue(res_ptr,0,c)};
            rp_.emplace(key,value);
        }
        PQclear(res_ptr);

        //get all first_level children for rp
        boost::json::array children {};
        rp_children_get(conn_ptr,rp_.at("id").as_string().c_str(),children);
        rp_.emplace("children",children);
        PQfinish(conn_ptr);

        msg=boost::json::serialize(rp_);
        return true;
    }
    return false;
}

//Check That User Authorized To Role Or Permission
bool dbase_handler::authz_check_get(const std::string &user_uid, const std::string &rp_ident, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    PGresult* res_ptr {NULL};
    {//check 'user_uid'
        const char* param_values[] {user_uid.c_str(),"false"};
        res_ptr=PQexecParams(conn_ptr,"SELECT * FROM users WHERE id=$1 AND is_blocked=$2",
                             2,NULL,param_values,NULL,NULL,0);

        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
        PQclear(res_ptr);
    }
    //empty rp_uid list for next use
    std::vector<std::string> rp_uids {};
    {//check 'rp_ident'
        const boost::regex& regex {"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"};
        boost::smatch match;
        if(!boost::regex_match(rp_ident,match,regex)){//not valid uuid, use as std::string
            //split by white_space and remove empty strings
            std::vector<std::string> rp_names {};
            boost::split(rp_names,rp_ident,boost::is_any_of("%20"),boost::token_compress_on);

            //get all rp_uids for rp_names
            rp_uids_by_rp_names_get(conn_ptr,rp_names,rp_uids);

            //get all low_level rp_uids for all top_level rp_uid in rp_uids
            std::vector<std::string> rp_uids_sub {};
            for(std::string& rp_uid: rp_uids){
                rp_uid_recursive_get(conn_ptr,rp_uid,rp_uids_sub);
            }
            std::copy(rp_uids_sub.begin(),rp_uids_sub.end(),std::back_inserter(rp_uids));
        }
        else{//valid uuid, use as 'rp_uuid'
            //get all low_level rp_uid for top_level rp_ident
            rp_uid_recursive_get(conn_ptr,rp_ident,rp_uids);
            rp_uids.push_back(rp_ident);
        }
    }
    if(rp_uids.empty()){
        PQfinish(conn_ptr);
        return false;
    }

    PQfinish(conn_ptr);
    return false;
}

//Assign Role Or Permission To User
bool dbase_handler::authz_manage_post(const std::string &requested_user_uid, const std::string &requested_rp_uid, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    {//check
        if(!is_user_exists(conn_ptr,requested_user_uid,msg) || !is_rp_exists(conn_ptr,requested_rp_uid,msg)){
            PQfinish(conn_ptr);
            return false;
        }
    }
    {//assign
        PGresult* res_ptr {NULL};
        const std::string& created_at {time_with_timezone()};

        const char* param_values[] {created_at.c_str(),requested_user_uid.c_str(),requested_rp_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,"INSERT INTO users_roles_permissions (created_at,user_id,role_permission_id) VALUES($1,$2,$3)",
                             3,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
    }
    {//send assigned role and permission back
        const char* param_values[] {requested_rp_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM roles_permissions WHERE id=$1",
                                       1,NULL,param_values,NULL,NULL,0);

        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }

        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};

        for(int c=0;c < columns;++c){
            const std::string& key {PQfname(res_ptr,c)};
            const std::string& value {PQgetvalue(res_ptr,0,c)};
            rp_.emplace(key,value);
        }
        PQclear(res_ptr);
        PQfinish(conn_ptr);

        msg=boost::json::serialize(rp_);
        return true;
    }
    return false;
}

//Revoke Role Or Permission From User
bool dbase_handler::authz_manage_delete(const std::string &requested_user_uid, const std::string &requested_rp_uid, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    {//check
        if(!is_user_exists(conn_ptr,requested_user_uid,msg) || !is_rp_exists(conn_ptr,requested_rp_uid,msg)){
            PQfinish(conn_ptr);
            return false;
        }
    }
    {//remove
        PGresult* res_ptr {NULL};
        const char* param_values[] {requested_user_uid.c_str(),requested_rp_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,"DELETE FROM users_roles_permissions WHERE user_id=$1 AND role_permission_id=$2",
                             2,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
    }
    {//send assigned role and permission back
        const char* param_values[] {requested_rp_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"SELECT * FROM roles_permissions WHERE id=$1",
                                       1,NULL,param_values,NULL,NULL,0);

        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }

        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};

        for(int c=0;c < columns;++c){
            const std::string& key {PQfname(res_ptr,c)};
            const std::string& value {PQgetvalue(res_ptr,0,c)};
            rp_.emplace(key,value);
        }
        PQclear(res_ptr);
        PQfinish(conn_ptr);

        msg=boost::json::serialize(rp_);
        return true;
    }
    return false;
}
