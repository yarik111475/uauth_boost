#include "app_settings.h"

app_settings::app_settings(std::string etc_uauth_dir, std::shared_ptr<spdlog::logger> logger_ptr)
    :etc_uauth_dir_{etc_uauth_dir},logger_ptr_{logger_ptr}
{
}

bool app_settings::settings_init()
{
    //server params
    params_.emplace("host","127.0.0.1");
    params_.emplace("port","8030");
    //db params
    params_.emplace("db_user","u-backend");
    params_.emplace("db_pass","u-backend");
    params_.emplace("db_host","dev3.u-system.tech");
    params_.emplace("db_port","5436");
    params_.emplace("db_name","u-auth");
    return true;
}

void app_settings::value_set(const std::string &key, const std::string &value)
{
    params_.emplace(key,value);
}

bool app_settings::value_get(const std::string &key, std::string &value)
{
    if(!params_.contains(key)){
        return false;
    }
    value=params_.at(key).as_string().c_str();
    return true;
}
