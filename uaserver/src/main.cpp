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

int main(int argc,char* argv[])
{
#if BOOST_OS_WINDOWS
    std::system("chcp 1251");
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
    const std::string home_dir {std::getenv("USERPROFILE")==NULL ? "" : getenv("USERPROFILE")};
#endif
#if BOOST_OS_LINUX
    const std::string home_dir {std::getenv("HOME")==NULL ? "" : getenv("HOME")};
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
