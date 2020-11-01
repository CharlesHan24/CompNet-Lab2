#ifndef _SIM_KERNEL_H
#define _SIM_KERNEL_H

#include <device.h>
#include <vector>

namespace Kernel{
    using std::vector;
    using Device::device_t;
    struct kernel_t{
        vector<device_t*> devices;
        
        int allo_device_id;

        kernel_t () {
            allo_device_id = 0;
        }
    }core;


    int addDevice(const char* device){

    }
}

#endif