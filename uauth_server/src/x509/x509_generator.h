#ifndef X509_GENERATOR_H
#define X509_GENERATOR_H

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <boost/json.hpp>

namespace spdlog{
    class logger;
}

class x509_generator
{
private:
    std::shared_ptr<spdlog::logger> logger_ptr_ {nullptr};
    bool decrypt_subject(const std::string& path,std::unordered_multimap<std::string,std::string>& subj_map,std::string& msg);

public:
    explicit x509_generator(std::shared_ptr<spdlog::logger> logger_ptr);
    ~x509_generator()=default;
    bool create_PKCS12(const std::string& user_id, const std::string& root_path, const std::string& pub_path,
                       const std::string& pr_path, const std::string& pr_pass, const std::string& pkcs_pass,
                       const std::string& pkcs_name, std::vector<char>& PKCS12_content, std::string& msg);
    bool create_X509(const std::string& pub_path,const std::string& pr_path,
                     const std::string& pr_pass,const std::vector<char>& x509_REQ_content,
                     std::vector<char>& x509_content,std::string& msg);
};

#endif // X509_GENERATOR_H
