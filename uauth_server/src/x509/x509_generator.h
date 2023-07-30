#ifndef X509_GENERATOR_H
#define X509_GENERATOR_H

#include <string>
#include <vector>
#include <memory>
#include <boost/json.hpp>

namespace spdlog{
    class logger;
}

class x509_generator
{
private:
    boost::json::object params_ {};
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};
public:
    explicit x509_generator(const boost::json::object& params,std::shared_ptr<spdlog::logger> logger_ptr);
    ~x509_generator()=default;

    bool sign_agent_crt(const std::vector<char>& csr_buffer,std::vector<char>& crt_buffer);
    bool create_user_crt(const std::string& user_uid,const std::string& crt_pass,std::vector<char>& crt_buffer);
};

#endif // X509_GENERATOR_H
