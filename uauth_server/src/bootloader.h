#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <boost/predef/os.h>

namespace spdlog{
    class logger;
}

class app_settings;
class http_uauth_server;

class bootloader
{
private:
    const int interval_ {2000};
    const std::string log_name_ {"Uauth"};
    const std::string log_filename_ {"uauth.log"};

    boost::asio::io_context& io_;
    boost::asio::deadline_timer timer_;

    std::string app_dir_;
    boost::json::object params_ {};

#if BOOST_OS_WINDOWS
    const std::string etc_dir_ {app_dir_ + "/../etc"};
    const std::string var_dir_ {app_dir_ + "/../var"};
#endif
#if BOOST_OS_LINUX
    const std::string etc_dir_ {/etc"};
    const std::string var_dir_ {/var"};
#endif
    const std::string etc_uauth_dir_ {etc_dir_ + "/uauth"};
    const std::string var_uauth_dir_ {var_dir_ + "/uauth"};
    const std::string var_log_uath_dir_ {var_dir_ + "/log/uauth"};

    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};
    std::shared_ptr<app_settings> app_settings_ptr_ {nullptr};
    std::shared_ptr<http_uauth_server> http_server_ptr_ {nullptr};

    bool init_dirs();
    void init_spdlog();
    bool start_listent();
    bool init_appsettings();
    void on_wait(const boost::system::error_code& ec);

public:
    explicit bootloader(boost::asio::io_context& io,const std::string& app_dir,const boost::json::object& params);
    ~bootloader()=default;

    void bootloader_start();
    void bootloader_stop();
};

#endif // BOOTLOADER_H
