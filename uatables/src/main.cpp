#include <iostream>

#include <iomanip>
#include <array>
#include <string>
#include <thread>
#include <vector>
#include <utility>
#include <cstdlib>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/date_time.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include "libpq-fe.h"

bool init_db_params(boost::json::object& params){
    //database params
    const std::string& UA_DB_NAME=std::getenv("UA_DB_NAME")==NULL ? "" :std::getenv("UA_DB_NAME");
    const std::string& UA_DB_HOST=std::getenv("UA_DB_HOST")==NULL ? "" :std::getenv("UA_DB_HOST");
    const std::string& UA_DB_PORT=std::getenv("UA_DB_PORT")==NULL ? "" :std::getenv("UA_DB_PORT");
    const std::string& UA_DB_USER=std::getenv("UA_DB_USER")==NULL ? "" :std::getenv("UA_DB_USER");
    const std::string& UA_DB_PASS=std::getenv("UA_DB_PASS")==NULL ? "" :std::getenv("UA_DB_PASS");

    params.emplace("UA_DB_NAME",UA_DB_NAME);
    params.emplace("UA_DB_HOST",UA_DB_HOST);
    params.emplace("UA_DB_PORT",UA_DB_PORT);
    params.emplace("UA_DB_USER",UA_DB_USER);
    params.emplace("UA_DB_PASS",UA_DB_PASS);

    auto it {params.begin()};
    while(it!=params.end()){
        if(it->value().is_string()){
            const std::string& value {it->value().as_string().c_str()};
            if(value.empty()){
                return false;
            }
        }
        ++it;
    }
    return true;
}

PGconn* open_connection(boost::asio::io_context& io,const boost::json::object& params,std::string& msg){
    PGconn* conn_ptr {NULL};
    const std::string& UA_DB_NAME {params.at("UA_DB_NAME").as_string().c_str()};
    const std::string& UA_DB_HOST {params.at("UA_DB_HOST").as_string().c_str()};
    const std::string& UA_DB_PORT {params.at("UA_DB_PORT").as_string().c_str()};
    const std::string& UA_DB_USER {params.at("UA_DB_USER").as_string().c_str()};
    const std::string& UA_DB_PASS {params.at("UA_DB_PASS").as_string().c_str()};

    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver r {io};
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

bool init_default_rps(PGconn *conn_ptr, std::string &msg)
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

bool tables_init(PGconn* conn_ptr,std::string& msg)
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

int main(int argc,char* argv[])
{
    boost::json::object params {};
    {//init and check db_params
        const bool& db_ok {init_db_params(params)};
        if(!db_ok){
            std::cerr<<"Database params initialization failed!"<<std::endl;
            return EXIT_FAILURE;
        }
    }

    PGconn* conn_ptr {NULL};
    std::string msg {};
    boost::asio::io_context io {};
    {//open connection
        conn_ptr=open_connection(io,params,msg);
        if(!conn_ptr){
            std::cerr<<"Fail to open connection to database, error:\n"<<msg<<std::endl;
            return EXIT_FAILURE;
        }
    }
    {//init tables
        const bool& ok {tables_init(conn_ptr,msg)};
        if(!ok){
            PQfinish(conn_ptr);
            std::cerr<<"Init tables failed, error: "<<msg<<std::endl;
            return EXIT_FAILURE;
        }
    }
    PQfinish(conn_ptr);
    std::cout<<"Init tables success"<<std::endl;
    return EXIT_SUCCESS;
}
