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

std::string time_with_timezone()
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

bool init_db_params(boost::json::object& params){
    //database params
    const std::string& UA_DB_NAME=std::getenv("UA_DB_NAME")==NULL ? "u-auth" :std::getenv("UA_DB_NAME");
    const std::string& UA_DB_HOST=std::getenv("UA_DB_HOST")==NULL ? "dev3.u-system.tech" :std::getenv("UA_DB_HOST");
    const std::string& UA_DB_PORT=std::getenv("UA_DB_PORT")==NULL ? "5436" :std::getenv("UA_DB_PORT");
    const std::string& UA_DB_USER=std::getenv("UA_DB_USER")==NULL ? "u-backend" :std::getenv("UA_DB_USER");
    const std::string& UA_DB_PASS=std::getenv("UA_DB_PASS")==NULL ? "u-backend" :std::getenv("UA_DB_PASS");

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

bool user_put(PGconn* conn_ptr,const boost::json::object& user,std::string& user_out,std::string& msg){
    PGresult* res_ptr {NULL};
    {//put user
        const std::string& id          {user.at("id").as_string().c_str()};
        const std::string& email       {user.at("email").as_string().c_str()};
        const std::string& location_id {user.at("location_id").as_string().c_str()};
        const std::string& ou_id       {user.at("ou_id").as_string().c_str()};

        const std::string& created_at {time_with_timezone()};
        const std::string& updated_at {time_with_timezone()};
        const std::string& is_blocked {std::to_string(false)};

        const char* param_values[] {id.c_str(),created_at.c_str(),updated_at.c_str(),email.c_str(),
                                    is_blocked.c_str(),location_id.c_str(),ou_id.c_str()};
        const std::string& query {"INSERT INTO users (id,created_at,updated_at,email,is_blocked,location_id,ou_id) "
                                    "VALUES($1,$2,$3,$4,$5,$6,$7)"};
        res_ptr=PQexecParams(conn_ptr,query.c_str(),7,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }
        PQclear(res_ptr);
    }
    {//get user back
        const std::string& id {user.at("id").as_string().c_str()};
        const char* param_values[] {id.c_str()};
        const std::string& command {"SELECT * FROM users WHERE id=$1"};
        res_ptr=PQexecParams(conn_ptr,command.c_str(),1,NULL,param_values,NULL,NULL,0);
        if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
            msg=std::string {PQresultErrorMessage(res_ptr)};
            PQclear(res_ptr);
            return false;
        }
        const int& rows {PQntuples(res_ptr)};
        if(!rows){
            PQclear(res_ptr);
            msg="user with id '" + id + "' not found";
            return false;
        }
        const int& columns {PQnfields(res_ptr)};
        boost::json::object user_ {};
        for(int c=0;c<columns;++c){
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
            user_.emplace(key,value);
        }
        user_out=boost::json::serialize(user_);
        PQclear(res_ptr);
        return true;
    }
    PQclear(res_ptr);
    return false;
}

bool rp_get(PGconn* conn_ptr,const std::string& rp_name, std::string& rp,std::string& msg)
{
    PGresult* res_ptr {NULL};
    const std::string& query {"SELECT * FROM roles_permissions WHERE name=$1"};
    const char* param_values[] {rp_name.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),1,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_TUPLES_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        return false;
    }
    const int& rows {PQntuples(res_ptr)};
    if(!rows){
        msg="role-permission with name: '" + rp_name + "' not found!";
        PQclear(res_ptr);
        PQfinish(conn_ptr);
        return false;
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
    rp=boost::json::serialize(rp_);
    return true;
}

bool urp_put(PGconn* conn_ptr, const std::string& user_id,const std::string& rp_id,std::string& msg)
{
    PGresult* res_ptr {NULL};
    const std::string& created_at {time_with_timezone()};
    const std::string& query {"INSERT INTO users_roles_permissions (created_at,user_id,role_permission_id) VALUES($1,$2,$3)"};
    const char* param_values[] {created_at.c_str(),user_id.c_str(),rp_id.c_str()};
    res_ptr=PQexecParams(conn_ptr,query.c_str(),3,NULL,param_values,NULL,NULL,0);
    if(PQresultStatus(res_ptr)!=PGRES_COMMAND_OK){
        msg=std::string {PQresultErrorMessage(res_ptr)};
        PQclear(res_ptr);
        return false;
    }
    PQclear(res_ptr);
    return true;
}

int main(int argc,char* argv[])
{
    const std::string& argv_start {argv[1]};
    if(argv_start!="create-super-user"){
        std::cerr<<"Ыtart parameter failed, mus be 'create-super-user'"<<std::endl;
        return EXIT_SUCCESS;
    }

    std::string user_id {};
    std::string email {};
    std::string location_id {};
    std::string ou_id {};
    boost::program_options::options_description desc("all options");
    desc.add_options()
            ("help", "enter user data in format: —user_id {uuid} --email {string} --location_id {uuid} --ou_id {uuid}")
            ("user_id",     boost::program_options::value<std::string>())
            ("email",       boost::program_options::value<std::string>())
            ("location_id", boost::program_options::value<std::string>())
            ("ou_id",       boost::program_options::value<std::string>());
    boost::program_options::variables_map vm;
    try{
        boost::program_options::store(boost::program_options::parse_command_line(argc,argv,desc),vm);
        boost::program_options::notify(vm);

        if(!vm.count("user_id") || !vm.count("email") || !vm.count("location_id") || !vm.count("ou_id")){
            std::cerr<<"reqired args 'user_id', 'email', 'location_id', 'ou_id' not found!"<<std::endl;
            return EXIT_SUCCESS;
        }
        user_id=vm.at("user_id").as<std::string>();
        email=vm.at("email").as<std::string>();
        location_id=vm.at("location_id").as<std::string>();
        ou_id=vm.at("ou_id").as<std::string>();
    }
    catch(const std::exception& ex){
        std::cerr<<"Уxception: "<<ex.what()<<std::endl;
        return EXIT_SUCCESS;
    }
    catch(...){
        std::cerr<<"Гnknown exception"<<std::endl;
        return EXIT_SUCCESS;
    }

    if(vm.count("help")){
        std::cout<<desc<<std::endl;
        return EXIT_SUCCESS;
    }

    const boost::json::object& user {
        {"id",user_id},
        {"email",email},
        {"location_id",location_id},
        {"ou_id",ou_id}
    };

    boost::json::object params {};
    {//init and check db_params
        const bool& db_ok {init_db_params(params)};
        if(!db_ok){
            std::cerr<<"Database params initialization failed!"<<std::endl;
            return EXIT_SUCCESS;
        }
    }

    PGconn* conn_ptr {NULL};
    std::string msg {};
    boost::asio::io_context io {};
    {//open connection
        conn_ptr=open_connection(io,params,msg);
        if(!conn_ptr){
            std::cerr<<"Fail to open connection to database, error:\n"<<msg<<std::endl;
            return EXIT_SUCCESS;
        }
    }
    std::string rp {};
    const bool& rp_ok {rp_get(conn_ptr,"UAuthAdmin",rp,msg)};
    if(!rp_ok){
        PQfinish(conn_ptr);
        std::cerr<<"Operation finished with failure, msg:\n"<<msg<<std::endl;
        return EXIT_SUCCESS;
    }
    boost::system::error_code ec;
    const boost::json::value& value_ {boost::json::parse(rp,ec)};
    if(ec){
        PQfinish(conn_ptr);
        std::cerr<<"Operation finished with failure, msg:\n"<<ec.message()<<std::endl;
        return EXIT_SUCCESS;
    }
    const boost::json::object& rp_obj {value_.as_object()};
    const std::string& role_permission_id {rp_obj.at("id").as_string().c_str()};

    std::string user_out {};
    const bool& user_ok {user_put(conn_ptr,user,user_out,msg)};

    if(!user_ok){
        PQfinish(conn_ptr);
        std::cerr<<"Operation finished with failure, msg:\n"<<msg<<std::endl;
        return EXIT_SUCCESS;
    }
    const bool& urp_ok {urp_put(conn_ptr,user_id,role_permission_id,msg)};
    if(!urp_ok){
        PQfinish(conn_ptr);
        std::cerr<<"Operation finished with failure, msg:\n"<<msg<<std::endl;
        return EXIT_SUCCESS;
    }
    PQfinish(conn_ptr);
    std::cout<<"Created user:\n"<<user_out<<"\n with role-permission:\n"<<rp<<std::endl;
    return EXIT_SUCCESS;
}
