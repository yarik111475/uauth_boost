#include "bootloader.h"
#include <settings/app_settings.h>
#include "network/http_server.h"
#include <ucontrol/uc_controller.h>

#include <vector>
#include <iostream>
#include <boost/format.hpp>
#include <boost/date_time.hpp>
#include <boost/bind/bind.hpp>
#include <boost/filesystem.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

bool bootloader::init_dirs()
{
    bool ok {true};
    boost::system::error_code ec;
    if(!boost::filesystem::exists(etc_dir_)){
        ok&=boost::filesystem::create_directories(etc_dir_,ec);
    }
    if(!boost::filesystem::exists(var_dir_)){
        ok&=boost::filesystem::create_directories(var_dir_,ec);
    }
    if(!boost::filesystem::exists(etc_uauth_dir_)){
        ok&=boost::filesystem::create_directories(etc_uauth_dir_,ec);
    }
    if(!boost::filesystem::exists(var_uauth_dir_)){
        ok&=boost::filesystem::create_directories(var_uauth_dir_,ec);
    }
    if(!boost::filesystem::exists(var_log_uath_dir_)){
        ok&=boost::filesystem::create_directories(var_log_uath_dir_,ec);
    }
    return ok;
}

void bootloader::init_spdlog()
{
    const int filesize {1024 * 1024 * 50};
    const int filescount {5};
    const spdlog::level::level_enum loglevel {spdlog::level::debug};

    boost::system::error_code ec;
    bool ok {boost::filesystem::exists(var_log_uath_dir_)};
    if(!ok){
        ok=boost::filesystem::create_directories(var_log_uath_dir_,ec);
    }

    const std::string& logfilename_path {var_log_uath_dir_ + "/" + log_filename_};
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    //sinks.push_back(std::make_shared<spdlog::sinks::daily_file_sink_mt>(path_to_log_file, 0, 0));
    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logfilename_path, filesize, filescount));

    logger_ptr_=spdlog::get(log_name_);
    if(!logger_ptr_){
        logger_ptr_.reset(new spdlog::logger(log_name_, sinks.begin(),sinks.end()));
        spdlog::register_logger(logger_ptr_);
        logger_ptr_->set_level(loglevel);
        logger_ptr_->flush_on(loglevel);
    }
}

bool bootloader::start_listen()
{
    http_server_ptr_.reset(new http_server{io_,app_dir_,app_settings_ptr_,logger_ptr_});
    if(!http_server_ptr_->server_listen()){
        http_server_ptr_.reset();
        return false;
    }
    uc_controller_ptr_->uc_status_signal_=
        std::bind(&http_server::uc_status_slot,http_server_ptr_.get(),std::placeholders::_1,std::placeholders::_2);
    return true;
}

bool bootloader::init_appsettings()
{
    app_settings_ptr_.reset(new app_settings{etc_uauth_dir_,logger_ptr_});
    return app_settings_ptr_->settings_init();
}

void bootloader::on_wait(const boost::system::error_code &ec)
{
    if(ec!=boost::asio::error::operation_aborted){
        {
            boost::system::error_code ec;
            const bool& listen_ok {start_listen()};
            if(listen_ok){
                timer_.cancel(ec);
                if(logger_ptr_){
                    logger_ptr_->info("{}, http_server started",
                        BOOST_CURRENT_FUNCTION);
                }
                return;
            }
            else{
                if(logger_ptr_){
                    logger_ptr_->critical("{}, start http_server failed",
                        BOOST_CURRENT_FUNCTION);
                }
            }
        }

        timer_.expires_from_now(boost::posix_time::milliseconds(interval_));
        timer_.async_wait(boost::bind(&bootloader::on_wait,this,boost::asio::placeholders::error));
    }
}

bootloader::bootloader(boost::asio::io_context &io, const std::string &app_dir, const std::string &home_dir, const boost::json::object &params)
    :io_{io},timer_{io_},app_dir_{app_dir},home_dir_{home_dir},params_{params}
{
    {//init all dirs
        const bool& dirs_ok {init_dirs()};
        if(!dirs_ok){
            const std::string& msg {(boost::format("%s, init all dirs failed")
                        % BOOST_CURRENT_FUNCTION).str()};
            std::cerr<<msg<<std::endl;
            exit(EXIT_FAILURE);
        }
    }
    {//init appsettings
        const bool& appsettings_ok {init_appsettings()};
        if(!appsettings_ok){
            const std::string& msg {(boost::format("%s, init appsettings failed")
                        % BOOST_CURRENT_FUNCTION).str()};
            std::cerr<<msg<<std::endl;
            exit(EXIT_FAILURE);
        }
    }
    init_spdlog();
}

void bootloader::bootloader_start()
{

    {//init and start http_server timer
        timer_.expires_from_now(boost::posix_time::milliseconds(interval_));
        timer_.async_wait(boost::bind(&bootloader::on_wait,this,boost::asio::placeholders::error));
    }
    {//init and start uc_controller
        const boost::json::object& params {
            {"UA_UC_HOST",app_settings_ptr_->value_get("UA_UC_HOST")},
            {"UA_UC_PORT",app_settings_ptr_->value_get("UA_UC_PORT")},
            {"UA_CA_CRT_PATH",app_settings_ptr_->value_get("UA_CA_CRT_PATH")},
            {"UA_CLIENT_CRT_PATH",app_settings_ptr_->value_get("UA_CLIENT_CRT_PATH")},
            {"UA_CLIENT_KEY_PATH",app_settings_ptr_->value_get("UA_CLIENT_KEY_PATH")},
            {"UA_CLIENT_KEY_PASS",app_settings_ptr_->value_get("UA_CLIENT_KEY_PASS")}
        };
        uc_controller_ptr_.reset(new uc_controller{io_,params,logger_ptr_});
        uc_controller_ptr_->controller_start();
    }

    if(logger_ptr_){
        logger_ptr_->info("{}, bootloader started",
            BOOST_CURRENT_FUNCTION);
    }
}

void bootloader::bootloader_stop()
{
    {//stop http_server
        if(http_server_ptr_){
            http_server_ptr_->server_stop();

        }
        boost::system::error_code ec;
        timer_.cancel(ec);
    }
    {//stop uc_controller
        if(uc_controller_ptr_){
            uc_controller_ptr_->controller_stop();
        }
    }

    if(logger_ptr_){
        logger_ptr_->info("{}, bootloader stopped",
                          BOOST_CURRENT_FUNCTION);
    }
}
