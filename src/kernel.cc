#include "kernel.h"
#include "common.h"

extern FILE* log_stream;
extern Kernel::kernel_t core;

namespace Kernel{

    void set_log_stream(FILE* redirect){
        log_stream = redirect;
    }
}