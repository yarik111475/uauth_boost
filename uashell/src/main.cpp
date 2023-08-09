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
    const std::string& id {user.at("id").as_string().c_str()};
    const std::string& created_at {user.at("created_at").as_string().c_str()};
    const std::string& updated_at {user.at("updated_at").as_string().c_str()};
    const std::string& first_name {user.at("first_name").as_string().c_str()};
    const std::string& last_name {user.at("last_name").as_string().c_str()};
    const std::string& email {user.at("email").as_string().c_str()};
    const std::string& is_blocked {std::to_string(user.at("is_blocked").as_bool())};
    const std::string& phone_number {user.at("phone_number").as_string().c_str()};
    const std::string& position {user.at("position").as_string().c_str()};
    const std::string& gender {user.at("gender").as_string().c_str()};
    const std::string& location_id {user.at("location_id").as_string().c_str()};
    const std::string& ou_id {user.at("ou_id").as_string().c_str()};

    const char* param_values[] {id.c_str(),created_at.c_str(),updated_at.c_str(),
                                first_name.c_str(),last_name.c_str(),email.c_str(),
                                is_blocked.c_str(),phone_number.c_str(),
                                position.c_str(),gender.c_str(),location_id.c_str(),ou_id.c_str()};
    const std::string& command {"INSERT INTO users (id,created_at,updated_at,first_name,last_name,email,is_blocked,phone_number,position,gender,location_id,ou_id) "
                                "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"};
    return false;
}

bool exec_user(boost::json::object& user,bool& need_continue){
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
            const bool& nullabale {pair.second};
            std::cout<<"Enter value for field: '"<<pair.first<<"', empty string for null,can be null: '"<<std::boolalpha<<pair.second<<"'\n";
            std::string field {};
            std::getline(std::cin,field);
            if(field.empty() && !pair.second){
                need_continue=true;
                std::cerr<<"Field '"<<pair.first<<"' can not be null, return  to start step!\n";
                std::cout<<"\n";
                return false;
            }
            user.emplace(pair.first,field);
        }
    }
    need_continue=false;
    return true;
}

int main(int argc,char* argv[])
{
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
    boost::json::object user {};
    {//execute user's loop
        bool need_continue {false};
        while(true){
            const bool& ok {exec_user(user,need_continue)};
            if(!ok){
                if(need_continue){
                    continue;
                }
                else{
                    std::cout<<"Operation was cancelled\nPress any key to exit.";
                    std::getchar();
                    break;
                }
            }
            else{
                const bool& ok {user_put(conn_ptr,user,msg)};
                if(!ok){
                    std::cout<<"Operation finished with failure, msg: "<<msg<<"\nPress any key to exit.";
                    std::getchar();
                    break;
                }
                else{
                    std::cout<<"Operation finished success, created user:\n"<<msg<<"\nPress any key to exit.";
                    std::getchar();
                    break;
                }
            }
        }
    }

    PQfinish(conn_ptr);
    return 0;
}
