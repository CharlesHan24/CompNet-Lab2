#ifndef _SIM_KERNEL_H
#define _SIM_KERNEL_H

#include "device.h"
#include "packetio.h"
#include <vector>

namespace Kernel{
    using std::vector;
    using Device::device_t;
    using Packet_IO::frameReceiveCallback;
    struct kernel_t{
        vector<device_t*> devices;
        
        int allo_device_id;
        frameReceiveCallback ether_cb;

        kernel_t () {
            allo_device_id = 0;
        }
    };

    void set_log_stream(FILE* redirect);
}

#endif