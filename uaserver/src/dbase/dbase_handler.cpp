#include "dbase_handler.h"

#include <vector>
#include <iostream>
#include <algorithm>
#include <boost/json.hpp>
#include <boost/regex.hpp>
#include <boost/format.hpp>
#include <boost/date_time.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/algorithm.hpp>

bool dbase_handler::is_initiated_ {true};

//Get date_time with timezone as std::string
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

//Open PGConnection
PGconn *dbase_handler::open_connection(std::string &msg)
{
    PGconn* conn_ptr {NULL};
    const std::string& UA_DB_NAME {params_.at("UA_DB_NAME").as_string().c_str()};
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
        % UA_DB_NAME).str()};

    conn_ptr=PQconnectdb(conninfo.c_str());
    if(PQstatus(conn_ptr)!=CONNECTION_OK){
        msg=std::string {PQerrorMessage(conn_ptr)};
        return nullptr;
    }
    return conn_ptr;
}

//Init tables if empty or not exists
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
                                    "last_name varchar(20) NULL, email varchar(60) NULL UNIQUE, is_blocked boolean NOT NULL, "
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
                                    "(id uuid PRIMARY KEY NOT NULL, name varchar(50) UNIQUE NOT NULL, "
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
                                    "(created_at timestamptz NOT NULL, "
                                    "user_id uuid NOT NULL references users, "
                                    "role_permission_id uuid NOT NULL references roles_permissions, "
                                    "primary key (user_id, role_permission_id))"};
        res_ptr=PQexec(conn_ptr,command.c_str());
        if(PQresultStatus(res_ptr) != PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }
    }
    {//create table 'roles_permissions_relationship'
        const std::string& command {"CREATE TABLE IF NOT EXISTS roles_permissions_relationship "
                                    "(created_at timestamptz NOT NULL, "
                                     "parent_id uuid NOT NULL references public.roles_permissions, "
                                     "child_id uuid NOT NULL references public.roles_permissions, "
                                     "primary key (parent_id, child_id))"};
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
            {"id","699bf280-70eb-552d-aae6-01341e2b8f33"},//2
            {"name","authorization_manage:update"},
            {"type","permission"},
            {"description","Assign role or permission to user"}
        },
        {
            {"id","d3722305-0489-51c1-8036-357ed6099c30"},//3
            {"name","role_permission:read"},
            {"type","permission"},
            {"description","List of roles and permissions; Get permission or role; Get permission or role with users;"}
        },
        {
            {"id","12892e88-9fbf-5915-b9b1-410b2bb1b42c"},//4
            {"name","role_permission:create"},
            {"type","permission"},
            {"description","Create permission or role"}
        },
        {
            {"id","e477530a-768d-5e87-bd79-a6c138edfef9"},//5
            {"name","role_permission:update"},
            {"type","permission"},
            {"description","Update permission or role"}
        },
        {
            {"id","005ece55-2703-5e10-9c20-561b87313b08"},//6
            {"name","role_permission:delete"},
            {"type","permission"},
            {"description","Delete permission or role"}
        },
        {
            {"id","4cabf4b7-c371-524b-8f32-7b0ac43a18e1"},//7
            {"name","user:read"},
            {"type","permission"},
            {"description","List of users; Get user info; Get user with role and permissions;"}
        },
        {
            {"id","5780bd9d-f6d9-5d14-b3fa-ffebc618f856"},//8
            {"name","user:create"},
            {"type","permission"},
            {"description","Create user"}
        },
        {
            {"id","a131af2b-0b1c-5a77-9589-0a0118c6b03b"},//9
            {"name","user:update"},
            {"type","permission"},
            {"description","Update user"}
        },
        {
            {"id","072a6653-025f-52b0-8653-f9528b9f2fee"},//10
            {"name","user:delete"},
            {"type","permission"},
            {"description","Delete user"}
        },
        {
            {"id","deb145a5-044f-5aed-befd-fc1f0a297aa0"},//11
            {"name","agent_certificate:create"},
            {"type","permission"},
            {"description","Sign agent certificate"}
        },
        {
            {"id","0c9e9550-6131-5a7d-a4fa-1fab41987ea5"},//12
            {"name","user_certificate:create"},
            {"type","permission"},
            {"description","Create user certificate"}
        },
        {
            {"id","a52851ae-b6d6-5df5-8534-8fb10d7a4eaa"},//13
            {"name","UAuthAdmin"},
            {"type","role"},
            {"description","Default Super User"}
        }
    };

    PGresult* res_ptr {NULL};
    for(const boost::json::value& v: default_rps){
        const boost::json::object& rp {v.as_object()};
        const std::string& id {rp.at("id").as_string().c_str()};
        const std::string& name {rp.at("name").as_string().c_str()};
        const std::string& type {rp.at("type").as_string().c_str()};
        const std::string& description {rp.at("description").as_string().c_str()};

        const char* param_values[] {id.c_str(),name.c_str(),type.c_str(),description.c_str()};
        res_ptr=PQexecParams(conn_ptr,"INSERT INTO roles_permissions (id,name,type,description) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
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

//Check if rp duplicate by name
bool dbase_handler::is_rp_duplicate(PGconn *conn_ptr, const std::string &name, std::string &msg)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT * FROM roles_permissions WHERE name=$1"};
    const char* param_values[] {name.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        return false;
    }

    PQclear(res_ptr);
    return true;
}

//Check if rp exists
bool dbase_handler::is_rp_exists(PGconn *conn_ptr, const std::string &rp_uid, std::string &msg)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
    const char* param_values[] {rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
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

//Check if user exists
bool dbase_handler::is_user_exists(PGconn *conn_ptr, const std::string &user_uid, std::string &msg)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT * FROM users WHERE id=$1"};
    const char* param_values[] {user_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
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

//Check if user authorized
bool dbase_handler::is_authorized(PGconn *conn_ptr, const std::string &user_uid, const std::string &rp_ident, std::string &msg)
{
    PGresult* res_ptr {NULL};
    std::vector<std::string> rp_uids {};
    {//get all rp_uid for user_uid
        const std::string& query {"SELECT role_permission_id FROM users_roles_permissions WHERE user_id=$1"};
        const char* param_values[] {user_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            PQclear(res_ptr);
            return false;
        }
        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            return false;
        }
        for(int r=0;r<rows;++r){
            const std::string& rp_uid {PQgetvalue(res_ptr,r,0)};
            rp_uids.push_back(rp_uid);
        }
        PQclear(res_ptr);

        {//check if UAuthAdmin role
            const std::string admin_rp_uid {uath_admin_rp_uid_get(conn_ptr)};
            const auto& it {std::find(rp_uids.begin(),rp_uids.end(),admin_rp_uid)};
            if(it!=rp_uids.end()){
                return true;
            }
        }
    }
    {//get all rp_uids recursive
        rp_uid_recursive_get(conn_ptr,rp_uids);
    }
    {//check if authorized
        boost::regex re {"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"};
        boost::smatch match;
        if(!boost::regex_match(rp_ident,match,re)){
            std::vector<std::string> rp_names {};
            boost::split(rp_names,rp_ident,boost::is_any_of("%20"),boost::token_compress_on);

            std::vector<std::string> rp_uids_names {};
            for(const std::string& rp_name: rp_names){
                const std::string& query {"SELECT id FROM roles_permissions WHERE name=$1"};
                const char* param_values[] {rp_name.c_str()};
                res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
                if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
                    PQclear(res_ptr);
                    return false;
                }
                const int& rows {PQntuples(res_ptr)};
                if(!rows){
                    PQclear(res_ptr);
                    return false;
                }
                for(int r=0;r<rows;++r){
                    const std::string& rp_uid_name {PQgetvalue(res_ptr,r,0)};
                    rp_uids_names.push_back(rp_uid_name.c_str());
                }
                PQclear(res_ptr);
            }
            const bool contains_all {std::all_of(rp_uids_names.begin(),rp_uids_names.end(),[&](const std::string& rp_uid){
                    const auto& it {std::find(rp_uids.begin(),rp_uids.end(),rp_uid)};
                    return (it!=rp_uids.end());
                })};
            return contains_all;
        }
        else{
            const auto& it {std::find(rp_uids.begin(),rp_uids.end(),rp_ident)};
            if(it!=rp_uids.end()){
                return true;
            }
        }
    }
    return false;
}

//Get total urp
int dbase_handler::urp_total_get(PGconn *conn_ptr)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT * FROM users_roles_permissions"};
    res_ptr=PQexec(conn_ptr,query.c_str());
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        PQclear(res_ptr);
        return 0;
    }

    const int& rows {PQntuples(res_ptr)};
    PQclear(res_ptr);
    return rows;
}

//Get total rps
int dbase_handler::rp_total_get(PGconn *conn_ptr)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT * FROM roles_permissions"};
    res_ptr=PQexec(conn_ptr,query.c_str());
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        PQclear(res_ptr);
        return 0;
    }

    const int& rows {PQntuples(res_ptr)};
    PQclear(res_ptr);
    return rows;
}

//Get total users
int dbase_handler::user_total_get(PGconn *conn_ptr)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT * FROM users"};
    res_ptr=PQexec(conn_ptr,query.c_str());
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        PQclear(res_ptr);
        return 0;
    }

    const int& rows {PQntuples(res_ptr)};
    PQclear(res_ptr);
    return rows;
}

//Get UAuthAdmin rp_uid
std::string dbase_handler::uath_admin_rp_uid_get(PGconn *conn_ptr)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT id FROM roles_permissions WHERE name=$1"};
    const char* param_values[] {"UAuthAdmin"};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        PQclear(res_ptr);
        return std::string {};
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        return std::string {};
    }
    const std::string& rp_uid {PQgetvalue(res_ptr,0,0)};
    PQclear(res_ptr);
    return rp_uid;
}

//Recursive get all low_level rp_uids by top_level rp_uid
void dbase_handler::rp_uid_recursive_get(PGconn *conn_ptr, std::vector<std::string>& rp_uids)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"WITH RECURSIVE rp_list AS ("
                                              "SELECT child_id, parent_id "
                                              "FROM roles_permissions_relationship "
                                               "WHERE parent_id IN ($1) "
                                               "UNION "
                                               "SELECT rpr.child_id, rpr.parent_id "
                                               "FROM roles_permissions_relationship rpr "
                                               "JOIN rp_list on rp_list.child_id = rpr.parent_id"
                                               ") SELECT DISTINCT child_id FROM rp_list"};

    std::vector<const char*> param_values {};
    param_values.resize(rp_uids.size());
    std::transform(rp_uids.begin(),rp_uids.end(),param_values.begin(),[](const std::string& item){
        return item.c_str();
    });
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values.data(),NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        PQclear(res_ptr);
        return;
    }
    const int& rows {PQntuples(res_ptr)};
    if(rows){
        for(int r=0;r<rows;++r){
            const char* rp_uid {PQgetvalue(res_ptr,r,0)};
            rp_uids.push_back(rp_uid);
        }
    }
    PQclear(res_ptr);
    return;
}

bool dbase_handler::rp_uids_child_get(PGconn *conn_ptr, const std::string &rp_uid, std::vector<std::string> &child_uids, std::string &msg)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT child_id FROM roles_permissions_relationship WHERE parent_id=$1"};
    const char* param_values[] {rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        return true;
    }

    for(int r=0;r < rows;++r){
        const char* rp_uid {PQgetvalue(res_ptr,r,0)};
        child_uids.push_back(rp_uid);
    }
    PQclear(res_ptr);
    return true;
}

bool dbase_handler::rp_uids_parent_get(PGconn *conn_ptr, const std::string &rp_uid, std::vector<std::string> &parent_uids, std::string &msg)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT parent_id FROM roles_permissions_relationship WHERE child_id=$1"};
    const char* param_values[] {rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        return false;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        return true;
    }

    for(int r=0;r < rows;++r){
        const char* rp_uid {PQgetvalue(res_ptr,r,0)};
        parent_uids.push_back(rp_uid);
    }
    PQclear(res_ptr);
    return true;
}

//Get all first_low_level rp_objects by top_level rp_uid
void dbase_handler::rp_children_get(PGconn *conn_ptr, const std::string &rp_uid, boost::json::array &rp_objs)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT child_id from roles_permissions_relationship WHERE parent_id=$1"};
    const char* param_values[]{rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
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
            const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
            const char* param_values[] {rp_uid.c_str()};
            PGresult* res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
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
                    const char* key {PQfname(res_ptr,c)};
                    const char* value {PQgetvalue(res_ptr,r,c)};
                    const int& is_null {PQgetisnull(res_ptr,r,c)};
                    rp_.emplace(key,is_null ? boost::json::value(nullptr) : value);
                }
                rp_objs.push_back(rp_);
            }
            PQclear(res_ptr);
        }
    }
}

//Get all rp_uids by rp_names
void dbase_handler::rp_uids_by_rp_names_get(PGconn *conn_ptr, const std::vector<std::string> &rp_names, std::vector<std::string> &rp_uids)
{
    PGresult* res_ptr {NULL};
    for(const std::string& rp_name: rp_names){
        const std::string& query {"SELECT id from roles_permissions WHERE name=$1"};
        const char* param_values[]{rp_name.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
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
            const char* rp_uid {PQgetvalue(res_ptr,r,0)};
            rp_uids.push_back(rp_uid==NULL ? nullptr : rp_uid);
        }
        PQclear(res_ptr);
    }
}

//Get all user_uids from 'users_roles_permissions' by rp_uid
bool dbase_handler::user_uids_by_rp_uid_get(PGconn *conn_ptr, const std::string &rp_uid, std::vector<std::string> &user_uids, std::string &msg)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT user_id FROM users_roles_permissions WHERE role_permission_id=$1"};
    const char* param_values[] {rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        return false;
    }
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        return true;
    }
    for(int r=0;r<rows;++r){
        const std::string& user_uid {PQgetvalue(res_ptr,r,0)};
        user_uids.push_back(user_uid);
    }
    PQclear(res_ptr);
    return true;
}

dbase_handler::dbase_handler(const boost::json::object &params, std::shared_ptr<spdlog::logger> logger_ptr)
    :io_{},params_{params},logger_ptr_{logger_ptr}
{
}

//Init database
bool dbase_handler::init_database(std::string &msg)
{
    if(dbase_handler::is_initiated_){
        return true;
    }
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return false;
    }
    if(!init_tables(conn_ptr,msg)){
        PQfinish(conn_ptr);
        return false;
    }
    PQfinish(conn_ptr);
    dbase_handler::is_initiated_=true;
    return true;
}

//List Of Users with limit and/or offset and filter
db_status dbase_handler::user_list_get(std::string& users, std::map<std::string, std::string> query_map,const std::string& requester_id,std::string& msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"user:read"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }

    //add limit/offset/filter
    int limit {100};
    int offset {0};
    std::string query {"SELECT * FROM users"};
    const auto& limit_it {query_map.find("limit")};
    if(limit_it!=query_map.end()){
        limit=std::stoi(limit_it->second);
        query_map.erase(limit_it);
    }
    const auto& offset_it {query_map.find("offset")};
    if(offset_it!=query_map.end()){
        offset=std::stoi(offset_it->second);
        query_map.erase(offset_it);
    }

    if(!query_map.empty()){
        query+=" WHERE";
        auto it {query_map.begin()};
        while(it!=query_map.end()){
            if(it->first=="first_name"){
                query+=" first_name ILIKE '%" + it->second + "%'";
            }
            else if(it->first=="last_name"){
                query+=" last_name ILIKE '%" + it->second + "%'";
            }
            else if(it->first=="email"){
                query+=" email = '" + it->second + "'";
            }
            else if(it->first=="is_blocked"){
                query+=" is_blocked = '" + it->second + "'";
            }
            else if(it->first=="phone_number"){
                query+=" phone_number ILIKE '%" + it->second + "%'";
            }
            else if(it->first=="position"){
                query+=" position ILIKE '%" + it->second + "%'";
            }
            else if(it->first=="gender"){
                query+=" gender = '" + it->second + "'";
            }
            query_map.erase(it++);
            if(!query_map.empty()){
                query+=" AND";
            }
        }
    }

    query+=" LIMIT " + std::to_string(limit);
    query+=" OFFSET " + std::to_string(offset);

    res_ptr=PQexec(conn_ptr,query.c_str());
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::not_found;
    }
    const int& columns {PQnfields(res_ptr)};

    boost::json::array users_ {};
    for(int r=0;r < rows;++r){
        boost::json::object user_ {};
        for(int c=0;c < columns;++c){
            const char* key {PQfname(res_ptr,c)};
            const char* value {PQgetvalue(res_ptr,r,c)};
            const int& is_null {PQgetisnull(res_ptr,r,c)};
            if(std::string {key}=="is_blocked"){
                const std::string& value_ {value};
                const bool& is_blocked {(value_.empty() || value_=="f") ? false : true};
                user_.emplace(key,is_blocked);
            }
            else{
                user_.emplace(key,is_null ? boost::json::value(nullptr) : value);
            }
        }
        users_.push_back(user_);
    }
    PQclear(res_ptr);
    const int& total {user_total_get(conn_ptr)};
    PQfinish(conn_ptr);

    const boost::json::object out {
        {"limit",limit},
        {"offset",offset},
        {"count",users_.size()},
        {"total",total},
        {"items",users_},
    };
    users=boost::json::serialize(out);
    return db_status::success;
}

//Get User Info
db_status dbase_handler::user_info_get(const std::string &user_uid, std::string &user, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"user:read"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    const std::string& query {"SELECT * FROM users WHERE id=$1"};
    const char* param_values[] {user_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        msg="user not found";
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::not_found;
    }

    const int& columns {PQnfields(res_ptr)};
    boost::json::object user_ {};

    for(int c=0;c < columns;++c){
        const char* key {PQfname(res_ptr,c)};
        const char* value {PQgetvalue(res_ptr,0,c)};
        const int& is_null {PQgetisnull(res_ptr,0,c)};
        if(std::string {key}=="is_blocked"){
            const std::string& value_ {value};
            const bool& is_blocked {(value_.empty() || value_=="f") ? false : true};
            user_.emplace(key,is_blocked);
        }
        else{
            user_.emplace(key,is_null ? boost::json::value(nullptr) : value);
        }
    }
    PQclear(res_ptr);
    PQfinish(conn_ptr);

    user=boost::json::serialize(user_);
    return db_status::success;
}

//Get User Assigned Roles And Permissions with limit and/or offset
db_status dbase_handler::user_rp_get(const std::string &user_uid, const std::string &limit, const std::string &offset, std::string &rps,const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"role_permission:read"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    int total {0};
    {//get 'total' users-roles-permissions by user_uid without LIMIT and OFFSET
        const char* param_values[] {user_uid.c_str()};
        const std::string& query {"SELECT * FROM users_roles_permissions WHERE user_id=$1"};
        res_ptr=PQexecParams(conn_ptr,query.c_str(), 1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            PQclear(res_ptr);
        }
        total=PQntuples(res_ptr);
        PQclear(res_ptr);
    }

    const char* param_values[] {user_uid.c_str()};
    std::string query {"SELECT role_permission_id FROM users_roles_permissions WHERE user_id=$1"};
    if(!limit.empty()){
        query += " LIMIT " + limit;
    }
    if(!offset.empty()){
        query += " OFFSET " + offset;
    }

    res_ptr=PQexecParams(conn_ptr,query.c_str(), 1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }

    boost::json::array rps_ {};
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        const boost::json::object& out {
            {"limit",limit.empty() ? 100 : std::stoi(limit)},
            {"offset",offset.empty() ? 0 : std::stoi(offset)},
            {"count",rps_.size()},
            {"total",total},
            {"items",rps_}
        };
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        rps=boost::json::serialize(out);
        return db_status::success;
    }
    else{
        std::vector<std::string> rp_ids {};
        for(int r=0;r<rows;++r){
            const std::string& rp_id {PQgetvalue(res_ptr,r,0)};
            rp_ids.push_back(rp_id);
        }
        for(const std::string& rp_id: rp_ids){
            const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
            const char* param_values[] {rp_id.c_str()};
            res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
            if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
                PQclear(res_ptr);
                continue;
            }
            const int& rows {PQntuples(res_ptr)};
            const int& columns {PQnfields(res_ptr)};
            boost::json::object rp_ {};
            for(int r=0;r<rows;++r){
                for(int c=0;c < columns;++c){
                    const char* key {PQfname(res_ptr,c)};
                    const char* value {PQgetvalue(res_ptr,r,c)};
                    const int& is_null {PQgetisnull(res_ptr,r,c)};
                    rp_.emplace(key,is_null ? boost::json::value(nullptr) : value);
                }
            }

            rps_.push_back(rp_);
            PQclear(res_ptr);
        }
    }
    PQfinish(conn_ptr);

    const boost::json::object& out {
        {"limit",limit.empty() ? 100 : std::stoi(limit)},
        {"offset",offset.empty() ? 0 : std::stoi(offset)},
        {"count",rps_.size()},
        {"total",total},
        {"items",rps_}
    };
    rps=boost::json::serialize(out);
    return db_status::success;
}

//Update User
db_status dbase_handler::user_info_put(const std::string &user_uid, const std::string &user, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"user:update"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    boost::json::object user_obj {};
    {//check user
        boost::system::error_code ec; 
        const boost::json::value& user_ {boost::json::parse(user,ec)};
        if(ec){
            msg="user not valid, error: " + ec.message();
            return db_status::fail;
        }
        user_obj=user_.as_object();

        std::set<std::string> fields_set {"first_name","last_name","email","is_blocked","phone_number","position","gender","location_id","ou_id"};
        std::set<std::string> keys_set  {};
        std::for_each(user_obj.begin(),user_obj.end(),[&](const boost::json::key_value_pair& pair){
            const std::string& key {pair.key()};
            keys_set.emplace(key);
        });

        for(const auto& field: fields_set){
            const auto& found {keys_set.find(field)};
            if(found==keys_set.end()){
                msg="user not valid, key '" + field + "' not exists";
                return db_status::fail;
            }
        }
    }

    //get user fields
    const char* first_name         {user_obj.at("first_name").is_null() ? nullptr : user_obj.at("first_name").as_string().c_str()};
    const char* last_name          {user_obj.at("last_name").is_null() ? nullptr : user_obj.at("last_name").as_string().c_str()};
    const char* email              {user_obj.at("email").is_null() ? nullptr : user_obj.at("email").as_string().c_str()};
    const std::string& is_blocked  {user_obj.at("is_blocked").is_null() ? nullptr : std::to_string(user_obj.at("is_blocked").as_bool())};
    const char* phone_number       {user_obj.at("phone_number").is_null() ? nullptr : user_obj.at("phone_number").as_string().c_str()};
    const char* position           {user_obj.at("position").is_null() ? nullptr : user_obj.at("position").as_string().c_str()};
    const char* gender             {user_obj.at("gender").is_null() ? nullptr : user_obj.at("gender").as_string().c_str()};
    const char* location_id        {user_obj.at("location_id").is_null() ? nullptr : user_obj.at("location_id").as_string().c_str()};
    const char* ou_id              {user_obj.at("ou_id").is_null() ? nullptr : user_obj.at("ou_id").as_string().c_str()};

    //auto-set fields
    const std::string& updated_at    {time_with_timezone()};

    {//update user
        const std::string& query {"UPDATE users SET first_name=$1,last_name=$2,email=$3,is_blocked=$4,updated_at=$5,"
                                                "phone_number=$6,position=$7,gender=$8,location_id=$9,ou_id=$10 WHERE id=$11"};
        const char* param_values[] {first_name,last_name,email,is_blocked.c_str(),updated_at.c_str(),
                                                      phone_number,position,gender,location_id,ou_id,user_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),11,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
        PQclear(res_ptr);
    }

    {//get updated user back
        const std::string& query {"SELECT * FROM users WHERE id=$1"};
        const char* param_values[] {user_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::not_found;
        }

        const int& columns {PQnfields(res_ptr)};
        boost::json::object user_ {};

        for(int c=0;c < columns;++c){
            const char* key {PQfname(res_ptr,c)};
            const char* value {PQgetvalue(res_ptr,0,c)};
            const int& is_null {PQgetisnull(res_ptr,0,c)};
            if(std::string {key}=="is_blocked"){
                const std::string& value_ {value};
                const bool& is_blocked {(value_.empty() || value_=="f") ? false : true};
                user_.emplace(key,is_blocked);
            }
            else{
                user_.emplace(key,is_null ? boost::json::value(nullptr) : value);
            }
        }
        PQclear(res_ptr);
        msg=boost::json::serialize(user_);
    }
    PQfinish(conn_ptr);
    return db_status::success;
}

//Create User
db_status dbase_handler::user_info_post(const std::string &user, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"user:create"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }

    boost::json::object user_obj {};
    {//check user
        boost::system::error_code ec;
        const boost::json::value& user_ {boost::json::parse(user,ec)};
        if(ec){
            msg="user not valid, error: " + ec.message();
            return db_status::fail;
        }
        user_obj=user_.as_object();

        std::set<std::string> fields_set {"id","first_name","last_name","email","phone_number","position","gender","location_id","ou_id"};
        std::set<std::string> keys_set  {};
        std::for_each(user_obj.begin(),user_obj.end(),[&](const boost::json::key_value_pair& pair){
            const std::string& key {pair.key()};
            keys_set.emplace(key);
        });

        for(const auto& field: fields_set){
            const auto& found {keys_set.find(field)};
            if(found==keys_set.end()){
                msg="user not valid, key '" + field + "' not exists";
                return db_status::fail;
            }
        }
    }
    {//create user
        //get user fields
        const char* id           {user_obj.at("id").is_null() ? nullptr : user_obj.at("id").as_string().c_str()};
        const char* first_name   {user_obj.at("first_name").is_null() ? nullptr : user_obj.at("first_name").as_string().c_str()};
        const char* last_name    {user_obj.at("last_name").is_null() ? nullptr : user_obj.at("last_name").as_string().c_str()};
        const char* email        {user_obj.at("email").is_null() ? nullptr : user_obj.at("email").as_string().c_str()};
        const char* phone_number {user_obj.at("phone_number").is_null() ? nullptr : user_obj.at("phone_number").as_string().c_str()};
        const char* position     {user_obj.at("position").is_null() ? nullptr : user_obj.at("position").as_string().c_str()};
        const char* gender       {user_obj.at("gender").is_null() ? nullptr : user_obj.at("gender").as_string().c_str()};
        const char* location_id  {user_obj.at("location_id").is_null() ? nullptr : user_obj.at("location_id").as_string().c_str()};
        const char* ou_id        {user_obj.at("ou_id").is_null() ? nullptr : user_obj.at("ou_id").as_string().c_str()};

        //auto-set fields
        const std::string& created_at {time_with_timezone()};
        const std::string& updated_at {time_with_timezone()};
        const std::string& is_blocked {std::to_string(false)};

        const std::string& query {"INSERT INTO users (id,first_name,last_name,email,created_at,updated_at,is_blocked,phone_number,position,gender,location_id,ou_id)"
                                                 " VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"};
        const char* param_values[] {id,first_name,last_name,email,created_at.c_str(),updated_at.c_str(),is_blocked.c_str(),
                                    phone_number,position,gender,location_id,ou_id};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),12,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
    }
    {//send created user back
        const char* id {user_obj.at("id").as_string().c_str()};;
        const  std::string&  query  {"SELECT * FROM users WHERE id=$1"};
        const char* param_values[] {id};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::not_found;
        }
        const int& columns {PQnfields(res_ptr)};

        boost::json::object user_ {};

        for(int c=0;c < columns;++c){
            const char* key {PQfname(res_ptr,c)};
            const char* value {PQgetvalue(res_ptr,0,c)};
            const int& is_null {PQgetisnull(res_ptr,0,c)};
            if(std::string {key}=="is_blocked"){
                const std::string& value_ {value};
                const bool& is_blocked {(value_.empty() || value_=="f") ? false : true};
                user_.emplace(key,is_blocked);
            }
            else{
                user_.emplace(key,is_null ? boost::json::value(nullptr) : value);
            }
        }
        PQclear(res_ptr);
        msg=boost::json::serialize(user_);
    }
    PQfinish(conn_ptr);
    return db_status::success;
}

//Delete User
db_status dbase_handler::user_info_delete(const std::string &user_uid, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"user:delete"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    const std::string& query {"DELETE FROM users WHERE id=$1"};
    const char* param_values[] {user_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }
    PQclear(res_ptr);
    PQfinish(conn_ptr);
    return db_status::success;
}

//List Of Roles And Permissions with limit and/or offset
db_status dbase_handler::rp_list_get(std::string &rps, std::map<std::string, std::string> query_map, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"role_permission:read"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    int limit {100};
    int offset {0};
    std::string query {"SELECT * FROM roles_permissions"};
    const auto& limit_it {query_map.find("limit")};
    if(limit_it!=query_map.end()){
        limit=std::stoi(limit_it->second);
        query_map.erase(limit_it);
    }
    const auto& offset_it {query_map.find("offset")};
    if(offset_it!=query_map.end()){
        offset=std::stoi(offset_it->second);
        query_map.erase(offset_it);
    }

    if(!query_map.empty()){
        query +=" WHERE";
        const auto& it {query_map.begin()};
        if(it->first=="type"){
            query+=" type = '" + it->second + "'";
        }
        if(it->first=="name"){
            query +=" name ILIKE '%" + it->second + "%'";
        }
        query_map.erase(it);
    }

    if(!query_map.empty()){
        query +=" AND";
        const auto& it {query_map.begin()};
        if(it->first=="type"){
            query+=" type = '" + it->second + "'";
        }
        if(it->first=="name"){
            query +=" name ILIKE '%" + it->second + "%'";
        }
        query_map.erase(it);
    }

    query+=" LIMIT " + std::to_string(limit);
    query+=" OFFSET " + std::to_string(offset);

    res_ptr=PQexec(conn_ptr,query.c_str());
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::not_found;
    }
    const int& columns {PQnfields(res_ptr)};
    boost::json::array rps_ {};

    for(int r=0;r < rows;++r){
        boost::json::object rp_ {};
        for(int c=0;c < columns;++c){
            const char* key {PQfname(res_ptr,c)};
            const char* value {PQgetvalue(res_ptr,r,c)};
            const int& is_null {PQgetisnull(res_ptr,r,c)};
            rp_.emplace(key,is_null ? boost::json::value(nullptr) : value);
        }
        rps_.push_back(rp_);
    }
    PQclear(res_ptr);
    const int& total {rp_total_get(conn_ptr)};
    PQfinish(conn_ptr);

    const boost::json::object& out {
        {"limit",limit},
        {"offset",offset},
        {"count",rps_.size()},
        {"total",total},
        {"items",rps_}
    };
    rps=boost::json::serialize(out);
    return db_status::success;
}

//Get Permission Or Role
db_status dbase_handler::rp_info_get(const std::string &rp_uid, std::string &rp, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"role_permission:read"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
    const char* param_values[] {rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::not_found;
    }
    const int& columns {PQnfields(res_ptr)};
    boost::json::object rp_ {};

    for(int c=0;c < columns;++c){
        const char* key {PQfname(res_ptr,c)};
        const char* value {PQgetvalue(res_ptr,0,c)};
        const int& is_null {PQgetisnull(res_ptr,0,c)};
        rp_.emplace(key,is_null ? boost::json::value(nullptr) : value);
    }
    PQclear(res_ptr);
    PQfinish(conn_ptr);

    rp=boost::json::serialize(rp_);
    return db_status::success;
}

//Get Associated Users
db_status dbase_handler::rp_user_get(const std::string &rp_uid, std::string &users, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"user:read"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    int total {0};
    {//get 'total' users-roles-permissions by rp_uid without LIMIT and OFFSET
        const char* param_values[] {rp_uid.c_str()};
        const std::string& query {"SELECT * FROM users_roles_permissions WHERE role_permission_id=$1"};
        res_ptr=PQexecParams(conn_ptr,query.c_str(), 1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            PQclear(res_ptr);
        }
        total=PQntuples(res_ptr);
        PQclear(res_ptr);
    }

    const char* param_values[] {rp_uid.c_str()};
    const std::string& query {"SELECT user_id FROM users_roles_permissions WHERE role_permission_id=$1"};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL, param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }

    boost::json::array users_ {};
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);

        const boost::json::object& out {
            {"limit",100},
            {"offset",0},
            {"count",users_.size()},
            {"total",total},
            {"items",users_}
        };
        users=boost::json::serialize(out);
        return db_status::success;
    }
    else{
        std::vector<std::string> user_ids {};
        for(int r=0;r<rows;++r){
            const std::string& user_id {PQgetvalue(res_ptr,r,0)};
            user_ids.push_back(user_id);
        }

        for(const std::string& user_id: user_ids){
            const char* param_values[] {user_id.c_str()};
            const std::string& query {"SELECT * FROM users WHERE id=$1"};
            res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
            if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
                PQclear(res_ptr);
                continue;
            }

            const int& rows {PQntuples(res_ptr)};
            const int& columns {PQnfields(res_ptr)};
            boost::json::object user_ {};
            for(int r=0;r<rows;++r){
                for(int c=0;c < columns;++c){
                    const char* key {PQfname(res_ptr,c)};
                    const char* value {PQgetvalue(res_ptr,r,c)};
                    const int& is_null {PQgetisnull(res_ptr,r,c)};
                    if(std::string {key}=="is_blocked"){
                        const std::string& value_ {value};
                        const bool& is_blocked {(value_.empty() || value_=="f") ? false : true};
                        user_.emplace(key,is_blocked);
                    }
                    else{
                        user_.emplace(key,is_null ? boost::json::value(nullptr) : value);
                    }
                }
            }
            users_.push_back(user_);
            PQclear(res_ptr);
        }
    }
    PQfinish(conn_ptr);

    const boost::json::object& out {
        {"limit",100},
        {"offset",0},
        {"count",users_.size()},
        {"total",total},
        {"items",users_}
    };
    users=boost::json::serialize(out);
    return db_status::success;
}

//Get Associated Users with limit and/or offset and filter
db_status dbase_handler::rp_user_get(const std::string &rp_uid, std::string &users, const std::string &limit, const std::string &offset, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"user:read"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    int total {0};
    {//get 'total' users-roles-permissions by rp_uid without LIMIT and OFFSET
        const char* param_values[] {rp_uid.c_str()};
        const std::string& query {"SELECT * FROM users_roles_permissions WHERE role_permission_id=$1"};
        res_ptr=PQexecParams(conn_ptr,query.c_str(), 1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            PQclear(res_ptr);
        }
        total=PQntuples(res_ptr);
        PQclear(res_ptr);
    }

    std::string query {"SELECT user_id FROM users_roles_permissions WHERE role_permission_id=$1"};
    if(!limit.empty()){
        query +=" LIMIT " + limit;
    }
    if(!offset.empty()){
        query +=" OFFSET " + offset;
    }

    const char* param_values[] {rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL, param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }

    boost::json::array users_ {};
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);

        const boost::json::object& out {
            {"limit",limit.empty() ? 100 : std::stoi(limit)},
            {"offset",offset.empty() ? 0 : std::stoi(offset)},
            {"count",users_.size()},
            {"total",total},
            {"items",users_}
        };
        users=boost::json::serialize(out);
        return db_status::success;
    }
    else{
        std::vector<std::string> user_ids {};
        for(int r=0;r<rows;++r){
            const std::string& user_id {PQgetvalue(res_ptr,r,0)};
            user_ids.push_back(user_id);
        }

        for(const std::string& user_id: user_ids){
            const char* param_values[] {user_id.c_str()};
            const std::string& query {"SELECT * FROM users WHERE id=$1"};
            res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
            if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
                PQclear(res_ptr);
                continue;
            }

            const int& rows {PQntuples(res_ptr)};
            const int& columns {PQnfields(res_ptr)};
            boost::json::object user_ {};

           for(int r=0;r<rows;++r){
               for(int c=0;c < columns;++c){
                   const char* key {PQfname(res_ptr,c)};
                   const char* value {PQgetvalue(res_ptr,r,c)};
                   const int& is_null {PQgetisnull(res_ptr,r,c)};
                   if(std::string {key}=="is_blocked"){
                       const std::string& value_ {value};
                       const bool& is_blocked {(value_.empty() || value_=="f") ? false : true};
                       user_.emplace(key,is_blocked);
                   }
                   else{
                       user_.emplace(key,is_null ? boost::json::value(nullptr) : value);
                   }
               }
           }
            users_.push_back(user_);
            PQclear(res_ptr);
        }
    }
    PQfinish(conn_ptr);

     const boost::json::object& out {
        {"limit",limit.empty() ? 100 : std::stoi(limit)},
        {"offset",offset.empty() ? 0 : std::stoi(offset)},
        {"count",users_.size()},
        {"total",total},
        {"items",users_}
    };
    users=boost::json::serialize(out);
    return db_status::success;
}

//Get Permission Or Role Detail
db_status dbase_handler::rp_rp_detail_get(const std::string &rp_uid, std::string &rp, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"role_permission:read"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
    const char* param_values[] {rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }

    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }
    const int& columns {PQnfields(res_ptr)};
    boost::json::object rp_ {};
    for(int c=0;c < columns;++c){
        const char* key {PQfname(res_ptr,c)};
        const char* value {PQgetvalue(res_ptr,0,c)};
        const int& is_null {PQgetisnull(res_ptr,0,c)};
        rp_.emplace(key,is_null ? boost::json::value(nullptr) : value);
    }
    PQclear(res_ptr);

    //get all first_level children for rp
    boost::json::array children {};
    rp_children_get(conn_ptr,rp_.at("id").as_string().c_str(),children);
    rp_.emplace("children",children);
    PQfinish(conn_ptr);

    rp=boost::json::serialize(rp_);
    return db_status::success;
}

//Create Permission Or Role
db_status dbase_handler::rp_info_post(const std::string &rp, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"role_permission:create"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }

    boost::json::object rp_obj {};
    {//check rp
        boost::system::error_code ec;
        const boost::json::value& rp_ {boost::json::parse(rp,ec)};
        if(ec){
            msg="role-permission not valid, error: " + ec.message();
            return db_status::fail;
        }
        rp_obj=rp_.as_object();

        std::set<std::string> fields_set {"name","type","description"};
        std::set<std::string> keys_set  {};
        std::for_each(rp_obj.begin(),rp_obj.end(),[&](const boost::json::key_value_pair& pair){
            const std::string& key {pair.key()};
            keys_set.emplace(key);
        });

        for(const auto& field: fields_set){
            const auto& found {keys_set.find(field)};
            if(found==keys_set.end()){
                msg="role-permission not valid, key '" + field + "' not exists";
                return db_status::fail;
            }
        }
    }

    //get rp fields
    const char* name        {rp_obj.at("name").is_null() ? nullptr : rp_obj.at("name").as_string().c_str()};
    const char* type        {rp_obj.at("type").is_null () ? nullptr : rp_obj.at("type").as_string().c_str()};
    const char* description {rp_obj.at("description").is_null() ? nullptr : rp_obj.at("description").as_string().c_str()};

    {//check if rp duplicate 'name'
        const bool& is_duplicate {is_rp_duplicate(conn_ptr,std::string{name},msg)};
        if(is_duplicate){
            msg="role/permission with name: '" + std::string{name} + "' already exists!";
            PQfinish(conn_ptr);
            return db_status::conflict;
        }
    }

    //auto-set fields
    const boost::uuids::uuid& uuid_ {boost::uuids::random_generator()()};
    const std::string& uuid {boost::uuids::to_string(uuid_)};

    {//create role-permission
        const std::string& query {"INSERT INTO roles_permissions (id,name,type,description) VALUES($1,$2,$3,$4)"};
        const char* param_values[] {uuid.c_str(),name,type,description};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),4,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
    }
    {//send created role-permission back
        const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
        const char* param_values[] {uuid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }

        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::not_found;
        }
        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};

        for(int c=0;c < columns;++c){
            const char* key {PQfname(res_ptr,c)};
            const char* value {PQgetvalue(res_ptr,0,c)};
            const int& is_null {PQgetisnull(res_ptr,0,c)};
            rp_.emplace(key,is_null ? boost::json::value(nullptr) : value);
        }
        PQclear(res_ptr);
        msg=boost::json::serialize(rp_);
    }
    PQfinish(conn_ptr);
    return db_status::success;
}

//Update Permission Or Role
db_status dbase_handler::rp_info_put(const std::string &rp_uid, const std::string &rp, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"role_permission:update"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }

    boost::json::object rp_obj {};
    {//check rp
        boost::system::error_code ec;
        const boost::json::value& rp_ {boost::json::parse(rp,ec)};
        if(ec){
            msg="role-permission not valid, error: " + ec.message();
            return db_status::fail;
        }
        rp_obj=rp_.as_object();

        std::set<std::string> fields_set {"name","type","description"};
        std::set<std::string> keys_set  {};
        std::for_each(rp_obj.begin(),rp_obj.end(),[&](const boost::json::key_value_pair& pair){
            const std::string& key {pair.key()};
            keys_set.emplace(key);
        });

        for(const auto& field: fields_set){
            const auto& found {keys_set.find(field)};
            if(found==keys_set.end()){
                msg="role-permission not valid, key '" + field + "' not exists";
                return db_status::fail;
            }
        }
    }

    //get rp fields
    const char* name        {rp_obj.at("name").is_null() ? nullptr : rp_obj.at("name").as_string().c_str()};
    const char* type        {rp_obj.at("type").is_null () ? nullptr : rp_obj.at("type").as_string().c_str()};
    const char* description {rp_obj.at("description").is_null() ? nullptr : rp_obj.at("description").as_string().c_str()};

    {//update role-permmission
        const std::string& query {"UPDATE roles_permissions SET name=$1,type=$2,description=$3 WHERE id=$4"};
        const char* param_values[] {name,type,description,rp_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),4,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
        PQclear(res_ptr);
    }

    {//get updated role-permission back
        const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
        const char* param_values[] {rp_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::not_found;
        }

        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};
        for(int c=0;c < columns;++c){
            const char* key {PQfname(res_ptr,c)};
            const char* value {PQgetvalue(res_ptr,0,c)};
            const int& is_null {PQgetisnull(res_ptr,0,c)};
            rp_.emplace(key,is_null ? boost::json::value(nullptr) : value);
        }
        PQclear(res_ptr);
        msg=boost::json::serialize(rp_);   
    }
    PQfinish(conn_ptr);
    return db_status::success;
}

//Delete Permission Or Role
db_status dbase_handler::rp_info_delete(const std::string &rp_uid, const std::string& requester_id,std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if UAuthAdmin role
        const std::string admin_rp_uid {uath_admin_rp_uid_get(conn_ptr)};
        if(rp_uid==admin_rp_uid){
            msg="delete 'UAuthAdmin role impossible";
            return db_status::fail;
        }
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"role_permission:delete"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    {//check for 'users_roles_permissions' contans references
        std::vector<std::string> user_uids {};
        const bool& ok {user_uids_by_rp_uid_get(conn_ptr,rp_uid,user_uids,msg)};
        if(!ok){
            PQfinish(conn_ptr);
            return db_status::fail;
        }
        if(!user_uids.empty()){
            PQfinish(conn_ptr);
            const std::string& joined {boost::algorithm::join(user_uids,", ")};
            msg=(boost::format("%s assigned to users %s")
                                % rp_uid
                                % joined).str();
            return db_status::unprocessable_entity;
        }
    }
    {//check for 'roles_permissions_relationship' contans references
        std::vector<std::string> parent_child_uids {};
        if(rp_uids_child_get(conn_ptr,rp_uid,parent_child_uids,msg) &&
           rp_uids_parent_get(conn_ptr,rp_uid,parent_child_uids,msg)){
            if(!parent_child_uids.empty()){
                const std::string& joined {boost::algorithm::join(parent_child_uids,", ")};
                msg=(boost::format("%s parent/child for %s")
                                    % rp_uid
                                    % joined).str();
                return db_status::unprocessable_entity;
            }
        }
        else{
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
    }
    const std::string& query {"DELETE FROM roles_permissions WHERE id=$1"};
    const char* param_values[] {rp_uid.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return db_status::fail;
    }
    PQclear(res_ptr);
    PQfinish(conn_ptr);
    return db_status::success;
}

//Add Child To Role
db_status dbase_handler::rp_child_put(const std::string &parent_uid, const std::string &child_uid, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"role_permission:update"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    {//check if rp exists
        if(!is_rp_exists(conn_ptr,parent_uid,msg) || !is_rp_exists(conn_ptr,child_uid,msg)){
            PQfinish(conn_ptr);
            return db_status::not_found;
        }
    }
    {//create relationship
        const std::string& created_at {time_with_timezone()};
        const std::string& query {"INSERT INTO roles_permissions_relationship (created_at,parent_id,child_id) VALUES($1,$2,$3)"};
        const char* param_values[] {created_at.c_str(),parent_uid.c_str(),child_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),3,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
        PQclear(res_ptr);
    }
    {//send rp with all children back
        const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
        const char* param_values[] {parent_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }

        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::not_found;
        }
        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};

        for(int c=0;c < columns;++c){
            const char* key {PQfname(res_ptr,c)};
            const char* value {PQgetvalue(res_ptr,0,c)};
            const int& is_null {PQgetisnull(res_ptr,0,c)};
            rp_.emplace(key,value==NULL ? boost::json::value(nullptr) : value);
        }
        PQclear(res_ptr);

        //get all first_level children for rp
        boost::json::array children {};
        rp_children_get(conn_ptr,rp_.at("id").as_string().c_str(),children);
        rp_.emplace("children",children);
        PQfinish(conn_ptr);

        msg=boost::json::serialize(rp_);
        return db_status::success;
    }
    return db_status::fail;
}

//Remove Child From Role
db_status dbase_handler::rp_child_delete(const std::string &parent_uid, const std::string &child_uid, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"role_permission:update"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    {//check if rp exists
        if(!is_rp_exists(conn_ptr,parent_uid,msg) || !is_rp_exists(conn_ptr,child_uid,msg)){
            PQfinish(conn_ptr);
            return db_status::not_found;
        }
    }
    {//delete relationship
        const std::string& query {"DELETE FROM roles_permissions_relationship WHERE parent_id=$1 AND child_id=$2"};
        const char* param_values[] {parent_uid.c_str(),child_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),2,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
        PQclear(res_ptr);
    }
    {//send rp with all children back
        const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
        const char* param_values[] {parent_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }

        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::not_found;
        }
        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};

        for(int c=0;c < columns;++c){
            const char* key {PQfname(res_ptr,c)};
            const char* value {PQgetvalue(res_ptr,0,c)};
            const int& is_null {PQgetisnull(res_ptr,0,c)};
            rp_.emplace(key,is_null ? boost::json::value(nullptr) : value);
        }
        PQclear(res_ptr);

        //get all first_level children for rp
        boost::json::array children {};
        rp_children_get(conn_ptr,rp_.at("id").as_string().c_str(),children);
        rp_.emplace("children",children);
        PQfinish(conn_ptr);

        msg=boost::json::serialize(rp_);
        return db_status::success;
    }
    return db_status::fail;
}

//Check That User Authorized To Role Or Permission
db_status dbase_handler::authz_check_get(const std::string &user_uid, const std::string &rp_ident, bool &authorized, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    if(!conn_ptr){
        return db_status::fail;
    }
    authorized=is_authorized(conn_ptr,user_uid,rp_ident,msg);
    PQfinish(conn_ptr);
    return db_status::success;
}

//Assign Role Or Permission To User
db_status dbase_handler::authz_manage_post(const std::string &requested_user_uid, const std::string &requested_rp_uid, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"authorization_manage:update"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    {//check if user exists
        if(!is_user_exists(conn_ptr,requested_user_uid,msg) || !is_rp_exists(conn_ptr,requested_rp_uid,msg)){
            PQfinish(conn_ptr);
            return db_status::not_found;
        }
    }
    {//assign
        const std::string& created_at {time_with_timezone()};
        const std::string& query {"INSERT INTO users_roles_permissions (created_at,user_id,role_permission_id) VALUES($1,$2,$3)"};
        const char* param_values[] {created_at.c_str(),requested_user_uid.c_str(),requested_rp_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),3,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
        PQclear(res_ptr);
    }
    {//send assigned role and permission back
        const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
        const char* param_values[] {requested_rp_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }

        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::not_found;
        }
        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};

        for(int c=0;c < columns;++c){
            const char* key {PQfname(res_ptr,c)};
            const char* value {PQgetvalue(res_ptr,0,c)};
            const int& is_null {PQgetisnull(res_ptr,0,c)};
            rp_.emplace(key,is_null ? boost::json::value(nullptr) : value);
        }
        PQclear(res_ptr);
        PQfinish(conn_ptr);

        msg=boost::json::serialize(rp_);
        return db_status::success;
    }
    return db_status::fail;
}

//Revoke Role Or Permission From User
db_status dbase_handler::authz_manage_delete(const std::string &requested_user_uid, const std::string &requested_rp_uid, const std::string &requester_id, std::string &msg)
{
    PGconn* conn_ptr {open_connection(msg)};
    PGresult* res_ptr {NULL};
    if(!conn_ptr){
        return db_status::fail;
    }
    {//check if authorized
        std::string msg {};
        const std::string& rp_ident {"authorization_manage:update"};
        const bool& authorized {is_authorized(conn_ptr,requester_id,rp_ident,msg)};
        if(!authorized){
            PQfinish(conn_ptr);
            return db_status::unauthorized;
        }
    }
    {//check if user exists
        if(!is_user_exists(conn_ptr,requested_user_uid,msg) || !is_rp_exists(conn_ptr,requested_rp_uid,msg)){
            PQfinish(conn_ptr);
            return db_status::not_found;
        }
    }
    {//remove
        const std::string& query {"DELETE FROM users_roles_permissions WHERE user_id=$1 AND role_permission_id=$2"};
        const char* param_values[] {requested_user_uid.c_str(),requested_rp_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),2,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }
        PQclear(res_ptr);
    }
    {//send assigned role and permission back
        const std::string& query {"SELECT * FROM roles_permissions WHERE id=$1"};
        const char* param_values[] {requested_rp_uid.c_str()};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::fail;
        }

        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            PQfinish(conn_ptr);
            return db_status::not_found;
        }
        const int& columns {PQnfields(res_ptr)};
        boost::json::object rp_ {};

        for(int c=0;c < columns;++c){
            const char* key {PQfname(res_ptr,c)};
            const char* value {PQgetvalue(res_ptr,0,c)};
            const int& is_null {PQgetisnull(res_ptr,0,c)};
            rp_.emplace(key,is_null ? boost::json::value(nullptr) : value);
        }
        PQclear(res_ptr);
        PQfinish(conn_ptr);

        msg=boost::json::serialize(rp_);
        return db_status::success;
    }
    return db_status::fail;
}
