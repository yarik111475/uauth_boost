#include <string>
#include <thread>
#include <vector>
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

    {//start bootloader
        const boost::json::object& params {
        };
        bootloader b_loader {io,app_dir,params};
        b_loader.bootloader_start();
        io.run();
        b_loader.bootloader_stop();
    }

    for(std::thread& t: threads){
        if(t.joinable()){
            t.join();
        }
    }
    return 0;
}
