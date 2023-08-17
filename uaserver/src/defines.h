#ifndef DEFINES_H
#define DEFINES_H

enum class db_status{
    fail,
    success,
    conflict,
    not_found,
    unauthorized,
    unprocessable_entity
};

enum class uc_status{
    fail,
    success,
    bad_gateway,
    bad_request,
    failed_dependency

};

#endif // DEFINES_H
