#ifndef APP_SETTINGS_H
#define APP_SETTINGS_H

#include <string>
#include <memory>
#include <boost/any.hpp>
#include <boost/json.hpp>

namespace spdlog{
    class logger;
}

class app_settings
{
private:  
    boost::any etc_uauth_dir_ {};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};
    boost::json::object params_ {};

public:
    explicit app_settings(std::string etc_uauth_dir,std::shared_ptr<spdlog::logger> logger_ptr);
    bool settings_init();
    void value_set(const std::string& key,const std::string& value);
    std::string value_get(const std::string& key);
};

#endif // APP_SETTINGS_H
