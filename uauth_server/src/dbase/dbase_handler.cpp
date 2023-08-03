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
    const std::string& UA_DB {params_.at("UA_DB").as_string().c_str()};
    const std::string& UA_DB_HOST {params_.at("UA_DB_HOST").as_string().c_str()};
    const std::string& UA_DB_PORT {params_.at("UA_DB_PORT").as_string().c_str()};
    const std::string& UA_DB_USER {params_.at("UA_DB_USER").as_string().c_str()};
    const std::string& UA_DB_PASS {params_.at("UA_DB_PASS").as_string().c_str()};

    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver r {io_};
    const auto& ep_list {r.resolve(UA_DB_HOST,UA_DB_PORT,ec)};
    if(ec){
        msg=ec.message();
        return nullptr;
    }
    boost::asio::ip::tcp::endpoint ep {*ep_list.begin()};
    std::string conninfo {(boost::format("postgresql://%s:%s@%s:%d/%s?connect_timeout=10")
        % UA_DB_USER
        % UA_DB_PASS
        % ep.address().to_string()
        % ep.port()
        % UA_DB).str()};

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
    {//drop type if exists 'rolepermissiontype'
        const std::string& command {"DROP TYPE IF EXISTS rolepermissiontype"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            //return false;
        }
    }
    {//create type 'rolepermissiontype'
        const std::string& command {"CREATE TYPE rolepermissiontype AS ENUM ('role','permission')"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            //return false;
        }
    }
    {//drop type if exists 'gender'
        const std::string& command {"DROP TYPE IF EXISTS gender"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            //return false;
        }
    }
    {//create type 'gender'
        const std::string& command {"CREATE TYPE gender AS ENUM ('male','female')"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            //return false;
        }
    }
    {//create table 'users'
        const std::string& command {"CREATE TABLE IF NOT EXISTS users "
                                    "(id uuid PRIMARY KEY NOT NULL, created_at timestamptz NOT NULL, "
                                    "updated_at timestamptz NOT NULL, first_name varchar(20) NULL, "
                                    "last_name varchar(20) NULL, email varchar(60) NULL, is_blocked boolean NOT NULL, "
                                    "phone_number varchar NULL, position varchar NULL, "
                                    "gender gender NULL, location_id uuid NOT NULL, "
                                    "ou_id uuid NOT NULL)"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }
    }
    {//create table 'roles_permissions'
        const std::string& command {"CREATE TABLE IF NOT EXISTS roles_permissions "
                                    "(id uuid PRIMARY KEY NOT NULL, name varchar(50) NULL, "
                                    "description varchar NULL, type rolepermissiontype NULL)"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }

    }
    {//init default rps
        const bool default_rps_ok {init_default_rps(conn_ptr,msg)};
        if(!default_rps_ok){
            return false;
        }
    }
    {//create table 'users_roles_permissions'
        const std::string& command {"CREATE TABLE IF NOT EXISTS users_roles_permissions "
                                    "(created_at timestamptz NOT NULL, user_id uuid NOT NULL, role_permission_id uuid NOT NULL)"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }
    }
    {//create table 'roles_permissions_relationship'
        const std::string& command {"CREATE TABLE IF NOT EXISTS roles_permissions_relationship "
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

//init roles_permission with default values
bool dbase_handler::init_default_rps(PGconn *conn_ptr, std::string &msg)
{
    const boost::json::array& default_rps {
        {
            {"id","49c0b1c9-58f7-557d-9a73-ed4850431c01"},
            {"name","authorization_manage:read"},
            {"type","permission"},
            {"description","List roles or permissions assigned to user"}
        },
        {
            {"id","699bf280-70eb-552d-aae6-01341e2b8f33"},
            {"name","authorization_manage:update"},
            {"type","permission"},
            {"description","Assign role or permission to user"}
        },
        {
            {"id","d3722305-0489-51c1-8036-357ed6099c30"},
            {"name","roles_permissions:read"},
            {"type","permission"},
            {"description","List of roles and permissions; Get permission or role; Get permission or role with users;"}
        },
        {
            {"id","12892e88-9fbf-5915-b9b1-410b2bb1b42c"},
            {"name","roles_permissions:create"},
            {"type","permission"},
            {"description","Create permission or role"}
        },
        {
            {"id","e477530a-768d-5e87-bd79-a6c138edfef9"},
            {"name","roles_permissions:update"},
            {"type","permission"},
            {"description","Update permission or role"}
        },
        {
            {"id","005ece55-2703-5e10-9c20-561b87313b08"},
            {"name","roles_permissions:delete"},
            {"type","permission"},
            {"description","Delete permission or role"}
        },
        {
            {"id","4cabf4b7-c371-524b-8f32-7b0ac43a18e1"},
            {"name","users:read"},
            {"type","permission"},
            {"description","List of users; Get user info; Get user with role and permissions;"}
        },
        {
            {"id","5780bd9d-f6d9-5d14-b3fa-ffebc618f856"},
            {"name","users:create"},
            {"type","permission"},
            {"description","Create user"}
        },
        {
            {"id","a131af2b-0b1c-5a77-9589-0a0118c6b03b"},
            {"name","users:update"},
            {"type","permission"},
            {"description","Update user"}
        },
        {
            {"id","072a6653-025f-52b0-8653-f9528b9f2fee"},
            {"name","users:delete"},
            {"type","permission"},
            {"description","Delete user"}
        },
        {
            {"id","deb145a5-044f-5aed-befd-fc1f0a297aa0"},
            {"name","agent_certificates:create"},
            {"type","permission"},
            {"description","Sign agent certificate"}
        },
        {
            {"id","0c9e9550-6131-5a7d-a4fa-1fab41987ea5"},
            {"name","user_certificates:create"},
            {"type","permission"},
            {"description","Create user certificate"}
        }
    };

    for(const boost::json::value& v: default_rps){
        const boost::json::object& rp {v.as_object()};
        const std::string& id {rp.at("id").as_string().c_str()};
        const std::string& name {rp.at("name").as_string().c_str()};
        const std::string& type {rp.at("type").as_string().c_str()};
        const std::string& description {rp.at("description").as_string().c_str()};

        const char* param_values[] {id.c_str(),name.c_str(),type.c_str(),description.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"INSERT INTO roles_permissions (id,name,type,description) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
                                       4,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }
        PQclear(res_ptr);
    }
    return true;
}

//check if rp exists
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

//check if user exists
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

//get rows of 'users_roles_permissions' count
int dbase_handler::urp_total_get(PGconn *conn_ptr)
{
    const std::string& command {"SELECT id FROM users_roles_permissions"};
    PGresult* res_ptr=PQexec(conn_ptr,command.c_str());
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return -1;
    }
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return -1;
    }
    return rows;
}

//get rows of 'roles_permissions' count
int dbase_handler::rps_total_get(PGconn *conn_ptr)
{
    const std::string& command {"SELECT id FROM roles_permissions"};
    PGresult* res_ptr=PQexec(conn_ptr,command.c_str());
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return -1;
    }
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return -1;
    }
    return rows;
}

//get rows of 'users' count
int dbase_handler::users_total_get(PGconn *conn_ptr)
{
    const std::string& command {"SELECT id FROM users"};
    PGresult* res_ptr=PQexec(conn_ptr,command.c_str());
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return -1;
    }
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return -1;
    }
    return rows;
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

bool dbase_handler::init_database(std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    /*
    {//create database
        const std::string& UA_DB {params_.at("UA_DB").as_string().c_str()};
        const std::string& UA_DB_USER {params_.at("UA_DB_USER").as_string().c_str()};

        PGresult* res_ptr {NULL};
        const char* param_values[]{UA_DB.c_str(),UA_DB_USER.c_str()};
        res_ptr=PQexecParams(conn_ptr,"CREATE DATABASE $1 OWNER '$2'",
                             2,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return false;
        }
        PQclear(res_ptr);
    }
    */
    if(!init_tables(conn_ptr,msg)){
        PQfinish(conn_ptr);
        return false;
    }
    PQfinish(conn_ptr);
    return true;
}

//List Of Users
bool dbase_handler::users_list_get(std::string &users, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }

    PGresult* res_ptr=PQexec(conn_ptr,"SELECT * FROM users LIMIT 100 OFFSET 0");
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
    const int& total {users_total_get(conn_ptr)};
    PQfinish(conn_ptr);

    const boost::json::object out {
        {"limit",100},
        {"offset",0},
        {"count",users_.size()},
        {"total",total},
        {"items",users_},
    };
    users=boost::json::serialize(out);
    return true;
}

//List Of Users with limit and/or offset and filter
bool dbase_handler::users_list_get(std::string& users, const std::string& limit,
                                   const std::string& offset, const std::string &first_name,
                                   const std::string &last_name, const std::string &email,
                                   const std::string &is_blocked, std::string& msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    //add limit/offset
    std::string command {"SELECT * FROM users"};
    if(!limit.empty()){
        command += " LIMIT " + limit;
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
    const int& total {users_total_get(conn_ptr)};
    PQfinish(conn_ptr);

    const boost::json::object out {
        {"limit",limit},
        {"offset",offset},
        {"count",users_.size()},
        {"total",total},
        {"items",users_},
    };
    users=boost::json::serialize(out);
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
        msg="user not found";
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
    const int& total {rps_total_get(conn_ptr)};
    PQfinish(conn_ptr);

    const boost::json::object& out {
        {"limit",100},
        {"offset",0},
        {"count",rps_.size()},
        {"total",total},
        {"items",rps_}
    };
    rps=boost::json::serialize(out);
    return true;
}

//Get User Assigned Roles And Permissions with limit and/or offset
bool dbase_handler::users_rps_get(const std::string &user_uid, std::string &rps,
                                  const std::string &limit, const std::string &offset, std::string &msg)
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
            std::string command {"SELECT * FROM roles_permissions WHERE id=$1"};
            if(!limit.empty()){
                command += " LIMIT " + limit;
            }
            if(!offset.empty()){
                command += " OFFSET " + offset;
            }
            const char* param_values[] {rp_id.c_str()};
            PGresult* res_ptr=PQexecParams(conn_ptr,command.c_str(),
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
    const int& total {rps_total_get(conn_ptr)};
    PQfinish(conn_ptr);

    const boost::json::object& out {
        {"limit",limit},
        {"offset",offset},
        {"count",rps_.size()},
        {"total",total},
        {"items",rps_}
    };
    rps=boost::json::serialize(out);
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
    const std::string& phone_number {user_obj.at("phone_number").as_string().c_str()};
    const std::string& position {user_obj.at("position").as_string().c_str()};
    const std::string& gender {user_obj.at("gender").as_string().c_str()};
    const std::string& location_id {user_obj.at("location_id").as_string().c_str()};
    const std::string& ou_id {user_obj.at("ou_id").as_string().c_str()};

    const std::string& updated_at {time_with_timezone()};

    {//update user
        const char* param_values[] {first_name.c_str(),last_name.c_str(),email.c_str(),is_blocked.c_str(),updated_at.c_str(),
            phone_number.c_str(),position.c_str(),gender.c_str(),location_id.c_str(),ou_id.c_str(),user_uid.c_str()};
        PGresult* res_ptr=PQexecParams(conn_ptr,"UPDATE users SET first_name=$1,last_name=$2,email=$3,is_blocked=$4,updated_at=$5,"
                                                "phone_numder=$6,position=$7,gender=$8,location_id=8,ou_id=$10 WHERE id=$11",
                                                 11,NULL,param_values,NULL,NULL,0);
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
    const std::string& phone_number {user_obj.at("phone_number").as_string().c_str()};
    const std::string& position {user_obj.at("position").as_string().c_str()};
    const std::string& gender {user_obj.at("gender").as_string().c_str()};
    const std::string& location_id {user_obj.at("location_id").as_string().c_str()};
    const std::string& ou_id {user_obj.at("ou_id").as_string().c_str()};

    const boost::uuids::uuid& uuid_ {boost::uuids::random_generator()()};
    const std::string& uuid {boost::uuids::to_string(uuid_)};

    const std::string& created_at {time_with_timezone()};
    const std::string& updated_at {time_with_timezone()};

    const std::string& is_blocked {std::to_string(false)};

    const char* param_values[] {uuid.c_str(),first_name.c_str(),last_name.c_str(),email.c_str(),created_at.c_str(),updated_at.c_str(),is_blocked.c_str(),
                                phone_number.c_str(),position.c_str(),gender.c_str(),location_id.c_str(),ou_id.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,"INSERT INTO users (id,first_name,last_name,email,created_at,updated_at,is_blocked,phone_number,position,gender,location_id,ou_id)"
                                            " VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                                            12,NULL,param_values,NULL,NULL,0);
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
    const int& total {rps_total_get(conn_ptr)};
    PQfinish(conn_ptr);

    const boost::json::object& out {
        {"limit",100},
        {"offset",0},
        {"count",rps_.size()},
        {"total",total},
        {"items",rps_}
    };
    rps=boost::json::serialize(out);
    return true;
}

//List Of Roles And Permissions with limit and/or offset and filter
bool dbase_handler::rps_list_get(std::string &rps, const std::string &limit,
                                 const std::string offset,const std::string& name,
                                 const std::string& type,const std::string& description,std::string &msg)
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
    const int& total {rps_total_get(conn_ptr)};
    PQfinish(conn_ptr);

    const boost::json::object& out {
        {"limit",limit},
        {"offset",offset},
        {"count",rps_.size()},
        {"total",total},
        {"items",rps_}
    };
    rps=boost::json::serialize(out);
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
        const int& total {urp_total_get(conn_ptr)};
        PQfinish(conn_ptr);

        const boost::json::object& out {
            {"limit",100},
            {"offset",0},
            {"count",users_.size()},
            {"total",total},
            {"items",users_}
        };
        users=boost::json::serialize(out);
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
    const int& total {urp_total_get(conn_ptr)};
    PQfinish(conn_ptr);

    const boost::json::object& out {
        {"limit",100},
        {"offset",0},
        {"count",users_.size()},
        {"total",total},
        {"items",users_}
    };
    users=boost::json::serialize(out);
    return true;
}

bool dbase_handler::rps_users_get(const std::string &rp_uid, std::string &users, const std::string &limit, const std::string &offset, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }

    std::string command {"SELECT user_id FROM users_roles_permissions WHERE role_permission_id=$1"};
    if(!limit.empty()){
        command +=" LIMIT " + limit;
    }
    if(!offset.empty()){
        command +=" OFFSET " + offset;
    }

    const char* param_values[] {rp_uid.c_str()};
    PGresult* res_ptr=PQexecParams(conn_ptr,command.c_str(),
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
        const int& total {urp_total_get(conn_ptr)};
        PQfinish(conn_ptr);

        const boost::json::object& out {
            {"limit",limit},
            {"offset",offset},
            {"count",users_.size()},
            {"total",total},
            {"items",users_}
        };
        users=boost::json::serialize(out);
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
    const int& total {urp_total_get(conn_ptr)};
    PQfinish(conn_ptr);

     const boost::json::object& out {
        {"limit",limit},
        {"offset",offset},
        {"count",users_.size()},
        {"total",total},
        {"items",users_}
    };
    users=boost::json::serialize(out);
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
        boost::regex re {"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"};
        boost::smatch match;
        if(!boost::regex_match(rp_ident,match,re)){//not valid uuid, use as std::string
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
