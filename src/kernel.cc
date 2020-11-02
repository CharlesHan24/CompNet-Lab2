#include "kernel.h"
#include "common.h"

extern FILE* log_stream;
extern Kernel::kernel_t core;

namespace Kernel{
    kernel_t::kernel_t () {
        allo_device_id = 0;
    }

    kernel_t::~kernel_t () {
        int dev_cnt = devices.size();
        for (int i = 0; i < dev_cnt; i++){
            delete(devices[i]);
        }
    }
    
    void set_log_stream(FILE* redirect){
        log_stream = redirect;
    }
}