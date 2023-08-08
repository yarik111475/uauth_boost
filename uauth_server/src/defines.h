#ifndef DEFINES_H
#define DEFINES_H

enum class db_status{
    fail,
    success,
    not_found,
    unauthorized
};

enum class uc_status{
    fail,
    success,
    bad_gateway,
    failed_dependency
};

#endif // DEFINES_H
