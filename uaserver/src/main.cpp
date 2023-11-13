#include <string>
#include <thread>
#include <vector>
#include <cstdlib>
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <boost/predef/os.h>
#include <boost/filesystem.hpp>
#include <boost/asio/signal_set.hpp>

#include "bootloader.h"

#if BOOST_OS_WINDOWS
void set_env()
{
    //uauth server params
    _putenv("UA_HOST=127.0.0.1");
    _putenv("UA_PORT=8030");

    //ucontrol client params
    _putenv("UA_UC_HOST=127.0.0.1");
    _putenv("UA_UC_PORT=5678");

    //database params
    _putenv("UA_DB_NAME=");
    _putenv("UA_DB_HOST=");
    _putenv("UA_DB_PORT=");
    _putenv("UA_DB_USER=");
    _putenv("UA_DB_PASS=");

    _putenv("UA_DB_POOL_SIZE_MIN=1");
    _putenv("UA_DB_POOL_SIZE_MAX=100");
    _putenv("UA_LOG_LEVEL=0");


    _putenv("UA_ORIGINS=[http://127.0.0.1:8030]");
    _putenv("UA_SSL_WEB_CRT_VALID=365");

    //uauth certificates part
    _putenv("UA_CA_CRT_PATH=C:/x509/root-ca.pem");
    _putenv("UA_SIGNING_CA_CRT_PATH=C:/x509/signing-ca.pem");
    _putenv("UA_SIGNING_CA_KEY_PATH=C:/x509/signing-ca-key.pem");
    _putenv("UA_SIGNING_CA_KEY_PASS=");

    //ucontrol certificates part
    _putenv("UA_CLIENT_CRT_PATH=C:/x509/clientCert.pem");
    _putenv("UA_CLIENT_KEY_PATH=C:/x509/clientPrivateKey.pem");
    _putenv("UA_CLIENT_KEY_PASS=password");
}
#endif
#if BOOST_OS_LINUX
void set_env()
{
    //uauth server params
    setenv("UA_HOST","127.0.0.1",0);
    setenv("UA_PORT","8030",0);

    //ucontrol client params
    setenv("UA_UC_HOST","127.0.0.1",0);
    setenv("UA_UC_PORT","5678",0);

    //database params
    setenv("UA_DB_NAME","u-auth",0);
    setenv("UA_DB_HOST","dev3.u-system.tech",0);
    setenv("UA_DB_PORT","5436",0);
    setenv("UA_DB_USER","u-backend",0);
    setenv("UA_DB_PASS","u-backend",0);

    setenv("UA_DB_POOL_SIZE_MIN","1",0);
    setenv("UA_DB_POOL_SIZE_MAX","100",0);
    setenv("UA_LOG_LEVEL","0",0);


    setenv("UA_ORIGINS","[http://127.0.0.1:8030]",0);
    setenv("UA_SSL_WEB_CRT_VALID","365",0);

    //uauth certificates part
    setenv("UA_CA_CRT_PATH","/home/yaroslav/uauth/root-ca.pem",0);
    setenv("UA_SIGNING_CA_CRT_PATH","/home/yaroslav/uauth/signing-ca.pem",0);
    setenv("UA_SIGNING_CA_KEY_PATH","/home/yaroslav/uauth/signing-ca-key.pem",0);
    setenv("UA_SIGNING_CA_KEY_PASS","U$vN#@D,v)*$N9\\N",0);// U$vN#@D,v)*$N9\N

    //ucontrol certificates part
    setenv("UA_CLIENT_CRT_PATH","/home/yaroslav/ucontrol/clientCert.pem",0);
    setenv("UA_CLIENT_KEY_PATH","/home/yaroslav/ucontrol/clientPrivateKey.pem",0);
    setenv("UA_CLIENT_KEY_PASS","password",0);
}
#endif

int main(int argc,char* argv[])
{
#if BOOST_OS_WINDOWS
    std::system("chcp 1251");
    set_env();
#endif
#if BOOST_OS_LINUX
    set_env();
#endif
    boost::filesystem::path path_ {argv[0]};
    const std::string& app_dir {path_.remove_filename().string()};
    const unsigned int& max_threads {std::thread::hardware_concurrency()-1};

    boost::asio::io_context io;
    boost::asio::signal_set signals {io,SIGINT,SIGTERM};
    signals.async_wait([&](boost::system::error_code ec,int signum){
        io.stop();
    });

    std::vector<std::thread> threads;
    threads.reserve(max_threads);
    for(unsigned int i=0;i < max_threads;++i){
        threads.emplace_back([&](){
            io.run();
        });
    }
#if BOOST_OS_WINDOWS
    const std::string home_dir {std::getenv("USERPROFILE")==NULL ? "" : std::getenv("USERPROFILE")};
#endif
#if BOOST_OS_LINUX
    const std::string home_dir {std::getenv("HOME")==NULL ? "" : std::getenv("HOME")};
#endif

    {//start bootloader
        const boost::json::object& params {
        };
        bootloader bootloader_ {io,app_dir,home_dir,params};
        bootloader_.bootloader_start();
        io.run();
        bootloader_.bootloader_stop();
    }
    //wait for all threads finished
    for(std::thread& t: threads){
        if(t.joinable()){
            t.join();
        }
    }
    return 0;
}
