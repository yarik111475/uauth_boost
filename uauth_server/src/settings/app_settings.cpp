#include "app_settings.h"

#include <cstdlib>

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

    UA_DB_DSN_=std::getenv("UA_DB_DSN");
    UA_DB_POOL_SIZE_MIN_=std::getenv("UA_DB_POOL_SIZE_MIN");
    UA_DB_POOL_SIZE_MAX_=std::getenv("UA_DB_POOL_SIZE_MAX");
    UA_LOG_LEVEL_=std::getenv("UA_LOG_LEVEL");

    UA_ORIGINS_=std::getenv("UA_ORIGINS");
    UA_SSL_WEB_CRT_VALID_=std::getenv("UA_SSL_WEB_CRT_VALID");
    UA_CA_CRT_PATH_=std::getenv("UA_CA_CRT_PATH");
    UA_SIGNING_CA_CRT_PATH_=std::getenv("UA_SIGNING_CA_CRT_PATH");
    UA_SIGNING_CA_KEY_PATH_=std::getenv("UA_SIGNING_CA_KEY_PATH");
    UA_SIGNING_CA_KEY_PASS_=std::getenv("UA_SIGNING_CA_KEY_PASS");

    UA_SENTRY_DSN_=std::getenv("UA_SENTRY_DSN");
    UA_SENTRY_TRACES_SAMPLE_RATE_=std::getenv("UA_SENTRY_TRACES_SAMPLE_RATE");
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
