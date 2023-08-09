#include "uc_controller.h"
#include "https_client.h"

#include <boost/date_time.hpp>
#include <boost/bind/bind.hpp>
#include "spdlog/spdlog.h"

void uc_controller::on_wait(const boost::system::error_code &ec)
{
    if(ec!=boost::asio::error::operation_aborted){
        https_client_ptr_->client_run();
        timer_.expires_from_now(boost::posix_time::milliseconds(interval_));
        timer_.async_wait(boost::bind(&uc_controller::on_wait,this,boost::asio::placeholders::error));
    }
}


void uc_controller::uc_status_slot(uc_status status, const std::string &msg)
{
    if(uc_status_signal_){
        uc_status_signal_(status,msg);
    }
}

uc_controller::uc_controller(boost::asio::io_context &io, const boost::json::object &params, std::shared_ptr<spdlog::logger> logger_ptr)
    :io_{io},timer_{io_},params_{params},logger_ptr_{logger_ptr}
{
}

void uc_controller::controller_start()
{
    {//init https_client
        https_client_ptr_.reset(new https_client{io_,"",params_,logger_ptr_});
        https_client_ptr_->uc_status_signal_=
                std::bind(&uc_controller::uc_status_slot,this,std::placeholders::_1,std::placeholders::_2);
    }
    {//start timer
        timer_.expires_from_now(boost::posix_time::milliseconds(interval_));
        timer_.async_wait(boost::bind(&uc_controller::on_wait,this,boost::asio::placeholders::error));
    }

    if(logger_ptr_){
        logger_ptr_->info("{},uc_controller started",
            BOOST_CURRENT_FUNCTION);
    }
}

void uc_controller::controller_stop()
{
    boost::system::error_code ec;
    timer_.cancel(ec);
    if(logger_ptr_){
        logger_ptr_->info("{},uc_controller stopped",
            BOOST_CURRENT_FUNCTION);
    }
}
