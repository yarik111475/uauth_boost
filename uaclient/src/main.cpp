#include <iostream>

#include <string>
#include <thread>
#include <vector>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio/signal_set.hpp>

int main(int argc,char* argv[])
{
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
    for(int i=0;i < max_threads;++i){
        threads.emplace_back([&](){
            io.run();
        });
    }
    io.run();

    for(std::thread& t: threads){
        if(t.joinable()){
            t.join();
        }
    }
    return 0;
}
