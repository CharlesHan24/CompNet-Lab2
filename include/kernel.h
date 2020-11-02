#ifndef _SIM_KERNEL_H
#define _SIM_KERNEL_H

#include "device.h"
#include "packetio.h"
#include <vector>

namespace Kernel{
    using std::vector;
    using Device::device_t;
    using Packet_IO::frameReceiveCallback;

    /**
     * Definition of a "simulated" kernel type. 
     * The "simulated" kernel performs the layer 2 & 3 & 4 tasks.
     */
    struct kernel_t{
        vector<device_t*> devices;
        
        int allo_device_id;
        frameReceiveCallback ether_cb;
        
        kernel_t ();
        ~kernel_t ();
    };

    /**
     *  Redirect log info output stream to another FILE*.
     * 
     *  @param redirect
     *      The target output file stream.
     */
    void set_log_stream(FILE* redirect);
}

#endif