#include "app_settings.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include "spdlog/spdlog.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ini_parser.hpp>

app_settings::app_settings(std::string etc_uauth_dir, std::shared_ptr<spdlog::logger> logger_ptr)
    :etc_uauth_dir_{etc_uauth_dir},logger_ptr_{logger_ptr}
{
}

bool app_settings::settings_init()
{
    //uauth server params
    const std::string& UA_HOST=std::getenv("UA_HOST")==NULL ? "0.0.0.0" :std::getenv("UA_HOST");
    const std::string& UA_PORT=std::getenv("UA_PORT")==NULL ? "" :std::getenv("UA_PORT");

    //ucontrol client params
    const std::string& UA_UC_HOST=std::getenv("UA_UC_HOST")==NULL ? "" :std::getenv("UA_UC_HOST");
    const std::string& UA_UC_PORT=std::getenv("UA_UC_PORT")==NULL ? "" :std::getenv("UA_UC_PORT");

    //database params
    const std::string& UA_DB_NAME=std::getenv("UA_DB_NAME")==NULL ? "" :std::getenv("UA_DB_NAME");
    const std::string& UA_DB_HOST=std::getenv("UA_DB_HOST")==NULL ? "" :std::getenv("UA_DB_HOST");
    const std::string& UA_DB_PORT=std::getenv("UA_DB_PORT")==NULL ? "" :std::getenv("UA_DB_PORT");
    const std::string& UA_DB_USER=std::getenv("UA_DB_USER")==NULL ? "" :std::getenv("UA_DB_USER");
    const std::string& UA_DB_PASS=std::getenv("UA_DB_PASS")==NULL ? "" :std::getenv("UA_DB_PASS");

    const std::string& UA_DB_POOL_SIZE_MIN=std::getenv("UA_DB_POOL_SIZE_MIN")==NULL ? "" : std::getenv("UA_DB_POOL_SIZE_MIN");
    const std::string& UA_DB_POOL_SIZE_MAX=std::getenv("UA_DB_POOL_SIZE_MAX")==NULL ? "" : std::getenv("UA_DB_POOL_SIZE_MAX");
    const std::string& UA_LOG_LEVEL=std::getenv("UA_LOG_LEVEL")==NULL ? "" : std::getenv("UA_LOG_LEVEL");

    const std::string& UA_ORIGINS=std::getenv("UA_ORIGINS")==NULL ? "" : std::getenv("UA_ORIGINS");
    const std::string& UA_SSL_WEB_CRT_VALID=std::getenv("UA_SSL_WEB_CRT_VALID")==NULL ? "" : std::getenv("UA_SSL_WEB_CRT_VALID");

    //uauth certificates part
    const std::string& UA_CA_CRT_PATH=std::getenv("UA_CA_CRT_PATH")==NULL ? "" : std::getenv("UA_CA_CRT_PATH");
    const std::string& UA_SIGNING_CA_CRT_PATH=std::getenv("UA_SIGNING_CA_CRT_PATH")==NULL ? "" : std::getenv("UA_SIGNING_CA_CRT_PATH");
    const std::string& UA_SIGNING_CA_KEY_PATH=std::getenv("UA_SIGNING_CA_KEY_PATH")==NULL ? "" : std::getenv("UA_SIGNING_CA_KEY_PATH");
    const std::string& UA_SIGNING_CA_KEY_PASS=std::getenv("UA_SIGNING_CA_KEY_PASS")==NULL ? "" : std::getenv("UA_SIGNING_CA_KEY_PASS");

    //ucontrol certificates part
    const std::string& UA_CLIENT_CRT_PATH=std::getenv("UA_CLIENT_CRT_PATH")==NULL ? "" : std::getenv("UA_CLIENT_CRT_PATH");
    const std::string& UA_CLIENT_KEY_PATH=std::getenv("UA_CLIENT_KEY_PATH")==NULL ? "" : std::getenv("UA_CLIENT_KEY_PATH");
    const std::string& UA_CLIENT_KEY_PASS=std::getenv("UA_CLIENT_KEY_PASS")==NULL ? "" : std::getenv("UA_CLIENT_KEY_PASS");

    //sentry params
    const std::string& UA_SENTRY_DSN=std::getenv("UA_SENTRY_DSN")==NULL ? "" : std::getenv("UA_SENTRY_DSN");
    const std::string& UA_SENTRY_TRACES_SAMPLE_RATE=std::getenv("UA_SENTRY_TRACES_SAMPLE_RATE")==NULL ? "" : std::getenv("UA_SENTRY_TRACES_SAMPLE_RATE");

    params_.emplace("UA_HOST",UA_HOST);
    params_.emplace("UA_PORT",UA_PORT);

    params_.emplace("UA_UC_HOST",UA_UC_HOST);
    params_.emplace("UA_UC_PORT",UA_UC_PORT);

    params_.emplace("UA_DB_NAME",UA_DB_NAME);
    params_.emplace("UA_DB_HOST",UA_DB_HOST);
    params_.emplace("UA_DB_PORT",UA_DB_PORT);
    params_.emplace("UA_DB_USER",UA_DB_USER);
    params_.emplace("UA_DB_PASS",UA_DB_PASS);

    params_.emplace("UA_DB_POOL_SIZE_MIN",UA_DB_POOL_SIZE_MIN);
    params_.emplace("UA_DB_POOL_SIZE_MAX",UA_DB_POOL_SIZE_MAX);
    params_.emplace("UA_LOG_LEVEL",UA_LOG_LEVEL);

    params_.emplace("UA_ORIGINS",UA_ORIGINS);
    params_.emplace("UA_SSL_WEB_CRT_VALID",UA_SSL_WEB_CRT_VALID);

    params_.emplace("UA_CA_CRT_PATH",UA_CA_CRT_PATH);
    params_.emplace("UA_SIGNING_CA_CRT_PATH",UA_SIGNING_CA_CRT_PATH);
    params_.emplace("UA_SIGNING_CA_KEY_PATH",UA_SIGNING_CA_KEY_PATH);
    params_.emplace("UA_SIGNING_CA_KEY_PASS",UA_SIGNING_CA_KEY_PASS);

    params_.emplace("UA_CLIENT_CRT_PATH",UA_CLIENT_CRT_PATH);
    params_.emplace("UA_CLIENT_KEY_PATH",UA_CLIENT_KEY_PATH);
    params_.emplace("UA_CLIENT_KEY_PASS",UA_CLIENT_KEY_PASS);

    auto it {params_.begin()};
    while(it!=params_.end()){
        if(it->value().is_string()){
            const std::string& value {it->value().as_string().c_str()};
            if(value.empty()){
                return false;
            }
        }
        ++it;
    }

    params_.emplace("UA_SENTRY_DSN",UA_SENTRY_DSN);
    params_.emplace("UA_SENTRY_TRACES_SAMPLE_RATE",UA_SENTRY_TRACES_SAMPLE_RATE);

    const std::string& tree_ {boost::json::serialize(params_)};
    std::ofstream out_fs {etc_uauth_dir_ + "/" + filename_};
    out_fs<<tree_;
    out_fs.close();

    return true;
}

void app_settings::value_set(const std::string &key, const std::string &value)
{
    params_.emplace(key,value);
}

std::string app_settings::value_get(const std::string &key)
{
    if(!params_.contains(key)){
        return std::string{};
    }
    return std::string {params_.at(key).as_string().c_str()};
}
