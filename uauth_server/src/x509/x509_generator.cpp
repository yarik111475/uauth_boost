#include "x509_generator.h"

x509_generator::x509_generator(const boost::json::object &params, std::shared_ptr<spdlog::logger> logger_ptr)
    :params_{params},logger_ptr_{logger_ptr}
{    
}

bool x509_generator::sign_agent_crt(const std::vector<char> &csr_buffer, std::vector<char> &crt_buffer)
{
    return true;
}

bool x509_generator::create_user_crt(const std::string &user_uid, const std::string &crt_pass, std::vector<char> &crt_buffer)
{
    return true;
}
