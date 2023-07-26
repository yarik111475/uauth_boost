#ifndef APP_SETTINGS_H
#define APP_SETTINGS_H

#include <string>
#include <memory>
#include <boost/json.hpp>

namespace spdlog{
    class logger;
}

class app_settings
{
private:
    std::string UA_DB_DSN_ {};
    std::string UA_DB_POOL_SIZE_MIN_ {};
    std::string UA_DB_POOL_SIZE_MAX_ {};
    std::string UA_LOG_LEVEL_ {};

    std::string UA_ORIGINS_ {};
    std::string UA_SSL_WEB_CRT_VALID_ {};
    std::string UA_CA_CRT_PATH_ {};
    std::string UA_SIGNING_CA_CRT_PATH_ {};
    std::string UA_SIGNING_CA_KEY_PATH_ {};
    std::string UA_SIGNING_CA_KEY_PASS_ {};

    std::string UA_SENTRY_DSN_ {};
    std::string UA_SENTRY_TRACES_SAMPLE_RATE_ {};

    std::string etc_uauth_dir_ {};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};
    boost::json::object params_ {};

public:
    explicit app_settings(std::string etc_uauth_dir,std::shared_ptr<spdlog::logger> logger_ptr);
    bool settings_init();
    void value_set(const std::string& key,const std::string& value);
    bool value_get(const std::string& key,std::string& value);
};

#endif // APP_SETTINGS_H
