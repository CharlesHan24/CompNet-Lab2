#include "kernel.h"
#include "common.h"
#include "ip.h"
#include "arp.h"
#include "tcp.h"

extern FILE* log_stream;
extern Kernel::kernel_t core;

namespace Kernel{
    kernel_t::kernel_t () {
        allo_device_id = 0;
        quit_flag = 0;
        ARP_lyr::init();
        IP_lyr::init();
    }

    kernel_t::~kernel_t () {
        quit_flag = 1;
        int dev_cnt = devices.size();
        for (int i = 0; i < dev_cnt; i++){
            delete(devices[i]);
        }
        ARP_lyr::exiting();
        IP_lyr::exiting();
    }
    
    void set_log_stream(FILE* redirect){
        log_stream = redirect;
    }
}