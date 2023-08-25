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

bool user_put(PGconn* conn_ptr,const boost::json::object& user,std::string& msg){
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
        const std::string& command {"INSERT INTO users (id,created_at,updated_at,email,is_blocked,location_id,ou_id) "
                                    "VALUES($1,$2,$3,$4,$5,$6,$7)"};
        res_ptr=PQexecParams(conn_ptr,command.c_str(),7,NULL,param_values,NULL,NULL,0);
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
        msg=boost::json::serialize(user_);
        PQclear(res_ptr);
        return true;
    }
    PQclear(res_ptr);
    return false;
}

bool user_get(boost::json::object& user,bool& need_continue){
    start_lbl:
    std::cout<<"Enter command to execute and press 'Enter'\n"
             <<"Q or q (quit shell)\n"
             <<"CU or cu (create user)\n";
    std::string command {};
    std::getline(std::cin,command);
    boost::to_upper(command);

    if(command=="Q"){
        need_continue=false;
        return false;
    }
    if(command=="CU"){
        boost::uuids::uuid uuid_ {boost::uuids::random_generator()()};
        const std::string& id {boost::uuids::to_string(uuid_)};
        const std::string& created_at {time_with_timezone()};
        const std::string& updated_at {time_with_timezone()};
        const bool& is_blocked {false};

        user.emplace("id",id);
        user.emplace("created_at",created_at);
        user.emplace("updated_at",updated_at);
        user.emplace("is_blocked",is_blocked);

        std::array<std::pair<std::string,bool>,8> field_list {std::make_pair<std::string,bool>("first_name",true),
                                                              std::make_pair<std::string,bool>("last_name",true),
                                                              std::make_pair<std::string,bool>("email",true),
                                                              std::make_pair<std::string,bool>("phone_number",true),
                                                              std::make_pair<std::string,bool>("position",true),
                                                              std::make_pair<std::string,bool>("gender",true),
                                                              std::make_pair<std::string,bool>("location_id",false),
                                                              std::make_pair<std::string,bool>("ou_id",false)};
        for(const auto& pair: field_list){
            std::cout<<"Enter value for field: '"<<pair.first<<"', empty string for null,can be null: '"<<std::boolalpha<<pair.second<<"'\n";
            std::string field {};
            std::getline(std::cin,field);
            if(field.empty() && !pair.second){
                need_continue=true;
                std::cerr<<"Field '"<<pair.first<<"' can not be null, return  to start point!\n";
                std::cout<<"\n";
                return false;
            }
            user.emplace(pair.first,field);
        }
    }
    else{
        std::cerr<<"Unknown command,return to start point.\n";
        goto start_lbl;
    }
    need_continue=false;
    return true;
}

int main(int argc,char* argv[])
{
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
    }
    catch(const std::exception& ex){
        std::cerr<<"exception: "<<ex.what()<<std::endl;
        return EXIT_FAILURE;
    }
    catch(...){
        std::cerr<<"unknown exception"<<std::endl;
        return EXIT_FAILURE;
    }

    if(vm.count("help")){
        std::cout<<desc<<std::endl;
        return EXIT_SUCCESS;
    }

    if(!vm.count("user_id") || !vm.count("email") || !vm.count("location_id") || !vm.count("ou_id")){
        std::cerr<<"reqired args 'user_id', 'email', 'location_id', 'ou_id' not found!"<<std::endl;
        return EXIT_FAILURE;
    }
    user_id=vm.at("user_id").as<std::string>();
    email=vm.at("email").as<std::string>();
    location_id=vm.at("location_id").as<std::string>();
    ou_id=vm.at("ou_id").as<std::string>();

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
            std::cerr<<"Database params initialization failed!\n";
            exit(EXIT_FAILURE);
        }
    }

    PGconn* conn_ptr {NULL};
    std::string msg {};
    boost::asio::io_context io {};
    {//open connection
        conn_ptr=open_connection(io,params,msg);
        if(!conn_ptr){
            std::cerr<<"Fail to open connection to database, error: "<<msg<<"\n";
            exit(EXIT_FAILURE);
        }
    }
    const bool& ok {user_put(conn_ptr,user,msg)};
    PQfinish(conn_ptr);
    if(!ok){
        std::cerr<<"Operation finished with failure, msg:\n"<<msg<<"\nPress any key to exit.";
        std::getchar();
        return EXIT_FAILURE;
    }
    else{
        std::cout<<"Operation completed success, created user:\n"<<msg<<"\nPress any key to exit";
        std::getchar();
    }
    return 0;
}
