# Codelists

## Link Layer Implementation

- `./include/common.h` Some type definitions and utility functions.

- `./include/kernel.h`: The simulated kernel protocol stack. A `kernel_t` stores and manages all the states of the protocol stack.

- `./include/device.h`: Device management functions. It is worth noting that when launching a device for capturing, the function `launch` instantiates **another thread** for packet capturing to avoid blocking. Currently only support single thread sniffing on each device.
- `./include/packetio.h`: Functions for sending and receiving ethernet frames. We also implement a single debugging callback function `eth_debug_callback` that prints the info of the received packets and exits immediately. The real callback function will be provided within IP layer implementation in the next submission.
- `./test_scripts/eth_tests.cpp`, `./test_sctipts/eth_tests2.cpp`: A simple program that perform sanity checks on addDevice, sending ethernet frames and receiving ethernet frames.
    - First, build the virtual network with topology same as described in `./vnetutils/README.md`. Then 

