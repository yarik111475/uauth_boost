#include "bootloader.h"
#include <settings/app_settings.h>
#include "network/http_server.h"

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
#if BOOST_OS_WINDOWS
    if(!boost::filesystem::exists(etc_dir_)){
        ok&=boost::filesystem::create_directories(etc_dir_,ec);
    }
    if(!boost::filesystem::exists(var_dir_)){
        ok&=boost::filesystem::create_directories(var_dir_,ec);
    }
#endif
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
#if BOOST_OS_WINDOWS
    boost::system::error_code ec;
    bool ok {boost::filesystem::exists(app_dir_ + "/../var/log/uauth")};
    if(!ok){
        ok=boost::filesystem::create_directories(app_dir_ + "/../var/log/uauth",ec);
    }
    const std::wstring logfilename_path=ok ?
                        std::wstring{app_dir_.begin(),app_dir_.end()} + L"/../var/log/usagent/" + std::wstring{log_filename_.begin(),log_filename_.end()} :
                        std::wstring{app_dir_.begin(),app_dir_.end()} + L"/" + std::wstring{log_filename_.begin(),log_filename_.end()};

    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    //sinks.push_back(std::make_shared<spdlog::sinks::daily_file_sink_mt>(path_to_log_file, 0, 0));
    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logfilename_path, filesize, filescount));
#endif

#if BOOST_OS_LINUX
    boost::system::error_code ec;
    bool ok {boost::filesystem::exists("/var/log/usagent")};
    if(!ok){
        ok=boost::filesystem::create_directories("/var/log/usagent",ec);
    }

    const std::string& logfilename_path=ok ?
                std::string {"/var/log/uauth"} + "/" + log_filename_ :
                app_dir_ + "/" + log_filename_;

    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    //sinks.push_back(std::make_shared<spdlog::sinks::daily_file_sink_mt>(path_to_log_file, 0, 0));
    sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logfilename_path, filesize, filescount));
#endif

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

bootloader::bootloader(boost::asio::io_context &io, const std::string &app_dir, const boost::json::object &params)
    :io_{io},timer_{io_},app_dir_{app_dir},params_{params}
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
    //init and start timer
    timer_.expires_from_now(boost::posix_time::milliseconds(interval_));
    timer_.async_wait(boost::bind(&bootloader::on_wait,this,boost::asio::placeholders::error));
    if(logger_ptr_){
        logger_ptr_->info("{}, bootloader started",
            BOOST_CURRENT_FUNCTION);
    }
}

void bootloader::bootloader_stop()
{
     if(http_server_ptr_){
        http_server_ptr_->server_stop();
    }

    boost::system::error_code ec;
    timer_.cancel(ec);
    if(logger_ptr_){
        logger_ptr_->info("{}, bootloader stopped",
            BOOST_CURRENT_FUNCTION);
    }
}
