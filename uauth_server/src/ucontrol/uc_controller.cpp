#include "uc_controller.h"

void uc_controller::on_wait(boost::system::error_code &ec)
{

}

uc_controller::uc_controller(boost::asio::io_context &io, const boost::json::object &params, std::shared_ptr<spdlog::logger> logger_ptr)
    :io_{io},timer_{io_},params_{params},logger_ptr_{logger_ptr}
{

}

void uc_controller::controller_start()
{

}

void uc_controller::controller_stop()
{

}
