# CompNet-Lab2

- https://www.thegeekstuff.com/2012/04/route-examples/

- Routing的基本规则. mac address是一个local的概念, 如果destination address is within a range, 则利用ARP查询destination mac address并且送到哪里, 否则, packets are sent to the gateway: IP address是一个 global 概念. 

- 获取邻居 (下一跳) 的 IP信息: 给邻居发一个包, 邻居回复

- Routing table的格式:
    - Destination
    - Gateway
    - Genmask
    - Flags
    - Metric
    - Iface (device)

- TTL field: avoid loops in the network. Discard an IP packet when TTL = 0; else decrease TTL by one and forward it.

- https://tools.ietf.org/html/rfc826 arp

- Ethernet generally does not distinguish between multicast and broadcast. https://en.wikipedia.org/wiki/Multicast_address.

- ARP protocol:

    - https://www.zhihu.com/question/385028195/answer/1130665774
    - Destination mac address只是下一跳的address.

routing algorithm: flooding
每个节点维护曾经到达的packet. key: hash值, value: 到达的timestamp. 设置一个timeout, 

flooding是mac地址一般不设为broadcast. 通过ARP protocol问出: 对于每个device, 另一端连的若干device的IP, mac地址. 设置一个timeout, 一个device过了timeout后需要重新ARP.
