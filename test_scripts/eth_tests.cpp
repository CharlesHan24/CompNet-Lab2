#include "common.h"
#include "device.h"
#include "kernel.h"
#include "packetio.h"
#include <unistd.h>
#include <cstdio>

using namespace std;
FILE* log_stream = stdout;

Kernel::kernel_t core;

int main(int argc, char* argv[]){
    if (argc != 2){
        printf("Usage: ./test_eth_capture SPECIFIED_DEVICE\n");
        return 0;
    }

    Packet_IO::setFrameReceiveCallback(Packet_IO::eth_debug_callback);
    int ret_id = Device::addDevice(argv[1]);
    if (ret_id == -1){
        printf("Error on adding device\n");
        return 0;
    }

    Device::device_t* cur_device = Device::find_device_inst(ret_id);

    char payload[100];
    int len = 50;
    Packet_IO::sendFrame(payload, len, 0x0800, (void*)&cur_device->ethernet_addr, ret_id);
    sleep(20);


    return 0;
}