#include "app_settings.h"

#include <cstdlib>
#include "spdlog/spdlog.h"

app_settings::app_settings(std::string etc_uauth_dir, std::shared_ptr<spdlog::logger> logger_ptr)
    :etc_uauth_dir_{etc_uauth_dir},logger_ptr_{logger_ptr}
{
}

bool app_settings::settings_init()
{
    //server params
    const std::string& UA_HOST="127.0.0.1";
    const std::string& UA_PORT="8030";

    //db params
    const std::string& UA_DB="u-auth";
        //std::getenv("UA_DB")==NULL ? "" :std::getenv("UA_DB");
    const std::string& UA_DB_HOST="dev3.u-system.tech";
        //std::getenv("UA_DB_HOST")==NULL ? "" :std::getenv("UA_DB_HOST");
    const std::string& UA_DB_PORT="5436";
        //std::getenv("UA_DB_PORT")==NULL ? "" :std::getenv("UA_DB_PORT");
    const std::string& UA_DB_USER="u-backend";
        //std::getenv("UA_DB_USER")==NULL ? "" :std::getenv("UA_DB_USER");
    const std::string& UA_DB_PASS="u-backend";
        //std::getenv("UA_DB_PASS")==NULL ? "" :std::getenv("UA_DB_PASS");

    const std::string& UA_DB_POOL_SIZE_MIN="1";
        //std::getenv("UA_DB_POOL_SIZE_MIN")==NULL ? "" : std::getenv("UA_DB_POOL_SIZE_MIN");
    const std::string& UA_DB_POOL_SIZE_MAX="100";
        //std::getenv("UA_DB_POOL_SIZE_MAX")==NULL ? "" : std::getenv("UA_DB_POOL_SIZE_MAX");
    const std::string& UA_LOG_LEVEL="0";
        //std::getenv("UA_LOG_LEVEL")==NULL ? "" : std::getenv("UA_LOG_LEVEL");

    const std::string& UA_ORIGINS="[http://127.0.0.1:8030]";
        //std::getenv("UA_ORIGINS")==NULL ? "" : std::getenv("UA_ORIGINS");
    const std::string& UA_SSL_WEB_CRT_VALID="365";
        //std::getenv("UA_SSL_WEB_CRT_VALID")==NULL ? "" : std::getenv("UA_SSL_WEB_CRT_VALID");

    const std::string& UA_CA_CRT_PATH="C:/cert/root-ca.pem";
        //std::getenv("UA_CA_CRT_PATH")==NULL ? "" : std::getenv("UA_CA_CRT_PATH")

    const std::string& UA_SIGNING_CA_CRT_PATH="C:/cert/signing-ca.pem";
        //std::getenv("UA_SIGNING_CA_CRT_PATH")==NULL ? "" : std::getenv("UA_SIGNING_CA_CRT_PATH");

    const std::string& UA_SIGNING_CA_KEY_PATH="C:/cert/signing-ca-key.pem";
        //std::getenv("UA_SIGNING_CA_KEY_PATH")==NULL ? "" : std::getenv("UA_SIGNING_CA_KEY_PATH");

    const std::string& UA_SIGNING_CA_KEY_PASS="U$vN#@D,v)*$N9\\N";
        //std::getenv("UA_SIGNING_CA_KEY_PASS")==NULL ? "" : std::getenv("UA_SIGNING_CA_KEY_PASS");


    const std::string& UA_SENTRY_DSN="";
        //std::getenv("UA_SENTRY_DSN")==NULL ? "" : std::getenv("UA_SENTRY_DSN");
    const std::string& UA_SENTRY_TRACES_SAMPLE_RATE="";
        //std::getenv("UA_SENTRY_TRACES_SAMPLE_RATE")==NULL ? "" : std::getenv("UA_SENTRY_TRACES_SAMPLE_RATE");

    params_.emplace("UA_HOST",UA_HOST);
    params_.emplace("UA_PORT",UA_PORT);

    params_.emplace("UA_DB",UA_DB);
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

//    auto it {params_.begin()};
//    while(it!=params_.end()){
//        if(it->value().is_string()){
//            const std::string& value {it->value().as_string().c_str()};
//            if(value.empty()){
//                return false;
//            }
//        }
//        ++it;
//    }

    params_.emplace("UA_SENTRY_DSN",UA_SENTRY_DSN);
    params_.emplace("UA_SENTRY_TRACES_SAMPLE_RATE",UA_SENTRY_TRACES_SAMPLE_RATE);
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
