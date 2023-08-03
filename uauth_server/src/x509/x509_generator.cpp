#include "x509_generator.h"
#include <fstream>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/objects.h>
#include <openssl/x509_vfy.h>

bool x509_generator::decrypt_subject(const std::string &path, std::unordered_multimap<std::string, std::string> &subj_map, std::string &msg)
{
    std::ifstream in(path);
    std::istreambuf_iterator<char> begin {in};
    std::istreambuf_iterator<char> end {};

    const std::string content {begin,end};
    if(content.empty()){
        msg="crt content is empty!";
        return false;
    }

    int ret {0};
    BIO* bio {BIO_new(BIO_s_mem())};
    ret=BIO_write(bio, content.c_str(), content.size());
    if(ret<=0){
        BIO_free(bio);
        return false;
    }
    X509* x509 {PEM_read_bio_X509(bio, NULL, NULL, NULL)};
    X509_NAME* x509_name {X509_get_subject_name(x509)};
    const int& count {X509_NAME_entry_count(x509_name)};

    for(int i=0;i<count;++i){
        X509_NAME_ENTRY* entry {X509_NAME_get_entry(x509_name,i)};
        ASN1_OBJECT* obj {X509_NAME_ENTRY_get_object(entry)};
        ASN1_STRING* str {X509_NAME_ENTRY_get_data(entry)};

        const int& nid {OBJ_obj2nid(obj)};
        const std::string& key {OBJ_nid2sn(nid)};

        const int& str_length {str->length};
        unsigned char* buffer;
        ret=ASN1_STRING_to_UTF8(&buffer,str);
        if(ret!=str_length){
            msg="ASN1_STRING_to_UTF8 failed";
            return false;
        }
        buffer[str_length]='\0';
        std::string value {reinterpret_cast<const char*>(buffer)};
        subj_map.emplace(key,value);
    }
    X509_free(x509);
    BIO_free(bio);
    return true;
}

bool x509_generator::create_PKCS12(const std::string &user_id, const std::string &root_path,
                                   const std::string &pub_path, const std::string &pr_path,
                                   const std::string &pr_pass, const std::string &pkcs_pass,
                                   const std::string &pkcs_name, std::vector<char> &PKCS12_content, std::string &msg)
{
    try{
        int ret {};
        //create root X509
        std::shared_ptr<BIO> root_bio {BIO_new_file(root_path.c_str(),"r+"),&BIO_free};
        std::shared_ptr<X509> root_x509 {PEM_read_bio_X509(root_bio.get(),NULL,NULL,NULL),&X509_free};

        //create EVP_PKEY pub_key
        std::shared_ptr<BIO> pub_bio {BIO_new_file(pub_path.c_str(),"r+"),&BIO_free};
        std::shared_ptr<X509> pub_x509 {PEM_read_bio_X509(pub_bio.get(),NULL,NULL,NULL),&X509_free};
        std::shared_ptr<EVP_PKEY> pub_key {X509_get_pubkey(pub_x509.get()),&EVP_PKEY_free};
        X509_NAME* pub_name {X509_get_subject_name(pub_x509.get())};

        //create EVP_PKEY pr_key
        std::shared_ptr<BIO> pr_bio {BIO_new_file(pr_path.c_str(),"r+"),&BIO_free};
        std::shared_ptr<EVP_PKEY> pr_key {PEM_read_bio_PrivateKey(pr_bio.get(),NULL,NULL,(unsigned char*)pr_pass.c_str()),&EVP_PKEY_free};

        //create X509 object
        std::shared_ptr<X509> x509 {X509_new(),&X509_free};
        ret=X509_set_version(x509.get(),2L);
        X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
        X509_gmtime_adj(X509_get_notAfter(x509.get()), 31536000L * 3);
        ret=X509_set_pubkey(x509.get(),pub_key.get());
        ret=X509_set_issuer_name(x509.get(),pub_name);
        ret=X509_NAME_add_entry_by_txt(pub_name,"OU",MBSTRING_ASC,
                                       (const unsigned char*)"User",-1,-1,0);
        ret=X509_NAME_add_entry_by_txt(pub_name,"CN",MBSTRING_ASC,
                                       (const unsigned char*)user_id.c_str(),-1,-1,0);
        ret=X509_set_subject_name(x509.get(),pub_name);

        //sign X509 object
        ret=X509_sign(x509.get(),pr_key.get(),EVP_sha256());

        /*
        {//for .pem testing
            BIO* test_bio {BIO_new(BIO_s_mem())};
            ret=PEM_write_bio_X509(test_bio,x509.get());
            std::vector<char> test {};
            int l {BIO_pending(test_bio)};
            test.resize(l);
            BIO_read(test_bio,test.data(),l);
            std::ofstream out {"C:/cert/test.pem"};
            out.write(test.data(),test.size());
            out.close();
        }
        */

        //create and fill X509_stack
        std::shared_ptr<STACK_OF(X509)> sk_X509 {sk_X509_new_null(),&sk_X509_free};
        ret=sk_X509_push(sk_X509.get(),pub_x509.get());
        ret=sk_X509_push(sk_X509.get(),root_x509.get());

        //create PKCS12
        std::shared_ptr<PKCS12> pkcs {PKCS12_create(pkcs_pass.c_str(),pkcs_name.c_str(),pr_key.get(),x509.get(),sk_X509.get(),
                                     NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                     NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                                     20000,
                                     1,
                                     0),&PKCS12_free};
        //write PKCS12 content
        std::shared_ptr<BIO> pkcs_bio {BIO_new(BIO_s_mem()),&BIO_free};
        ret=i2d_PKCS12_bio(pkcs_bio.get(),pkcs.get());
        const int& pkcs_len {BIO_pending(pkcs_bio.get())};
        PKCS12_content.resize(pkcs_len);
        ret=BIO_read(pkcs_bio.get(),PKCS12_content.data(),PKCS12_content.size());
    }
    catch(const std::exception& ex){
        msg=ex.what();
        return false;
    }
    catch(...){
        msg="unknown exception";
        return false;
    }
    return true;
}

bool x509_generator::create_X509(const std::string &pub_path, const std::string &pr_path,
                                 const std::string &pr_pass, const std::vector<char> &x509_REQ_content,
                                 std::vector<char> &x509_content, std::string &msg)
{
    try{
        int ret {};
        //create agent X509_REQ
        std::shared_ptr<BIO> req_bio {BIO_new(BIO_s_mem()),&BIO_free};
        ret=BIO_write(req_bio.get(),x509_REQ_content.data(),x509_REQ_content.size());
        std::shared_ptr<X509_REQ> req {PEM_read_bio_X509_REQ(req_bio.get(),NULL,NULL,NULL),&X509_REQ_free};
        EVP_PKEY* req_key {X509_REQ_get0_pubkey(req.get())};
        X509_NAME* req_name {X509_REQ_get_subject_name(req.get())};

//        const int& name_count {X509_NAME_entry_count(req_name)};
//        for(int i=0;i<name_count;++i){
//            X509_NAME_ENTRY* entry {X509_NAME_get_entry(req_name,i)};
//            ASN1_OBJECT* obj {X509_NAME_ENTRY_get_object(entry)};
//            ASN1_STRING* str {X509_NAME_ENTRY_get_data(entry)};

//            const int& nid {OBJ_obj2nid(obj)};
//            const std::string& key {OBJ_nid2sn(nid)};
//            const int& len {str->length};
//        }

        //create EVP_PKEY pub_key
        std::shared_ptr<BIO> pub_bio {BIO_new_file(pub_path.c_str(),"r+"),&BIO_free};
        std::shared_ptr<X509> pub_x509 {PEM_read_bio_X509(pub_bio.get(),NULL,NULL,NULL),&X509_free};
        std::shared_ptr<EVP_PKEY> pub_key {X509_get_pubkey(pub_x509.get()),&EVP_PKEY_free};
        X509_NAME* pub_name {X509_get_subject_name(pub_x509.get())};

        //create EVP_PKEY pr_key
        std::shared_ptr<BIO> pr_bio {BIO_new_file(pr_path.c_str(),"r+"),&BIO_free};
        std::shared_ptr<EVP_PKEY> pr_key {PEM_read_bio_PrivateKey(pr_bio.get(),NULL,NULL,(unsigned char*)pr_pass.c_str()),&EVP_PKEY_free};

        //create X509 object
        std::shared_ptr<X509> x509 {X509_new(),&X509_free};
        ret=X509_set_version(x509.get(),2L);
        X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
        X509_gmtime_adj(X509_get_notAfter(x509.get()), 31536000L * 3);
        X509_set_subject_name(x509.get(),req_name);
        X509_set_issuer_name(x509.get(),pub_name);

        ret=X509_set_pubkey(x509.get(),req_key);
        ret=X509_sign(x509.get(),pr_key.get(),EVP_sha256());

        //write X509 content
        std::shared_ptr<BIO> x509_bio {BIO_new(BIO_s_mem()),&BIO_free};
        ret=PEM_write_bio_X509(x509_bio.get(),x509.get());
        const int& x509_len {BIO_pending(x509_bio.get())};
        x509_content.resize(x509_len);
        ret=BIO_read(x509_bio.get(),x509_content.data(),x509_content.size());
    }
    catch(const std::exception& ex){
        msg=ex.what();
        return false;
    }
    catch(...){
        msg="unknown exception";
        return false;
    }
    return true;
}

x509_generator::x509_generator(std::shared_ptr<spdlog::logger> logger_ptr)
    :logger_ptr_{logger_ptr}
{    
}

