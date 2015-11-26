PA1

Group members:
Shawn Krivorot | 999173399 | g2clouds
Akshay Mehra | 999990194 | g3mehraa
Ilan Karasik | 999675588 | g4karasi

Structure Overview:
Functionality for Receiving ICMP echo requests, sending ICMP echo replies and ICMP error messages was added. As well, forwarding IP packets, sending ARP requests and receiving ARP replies are all handled. The final piece of code added was handling the ARP cache. All functions related to handling the actual ARP cache are within sr_arpcache.c and all functions related to packet handling are within sr_router.c. This split allows us to make sure that sending and receiving ARP packets are grouped with all packets rather than performing packet handling in the sr_arpcache.c file seperately.


Design Decision:

For this router, the group decided to merge the 2 seperate structs for ICMP headers into 1 generic ICMP header. Through the view of the given links displaying the structure of the ICMP packets, it was noticed that for the various type values and code value in the ICMP header, the header itself was a consistent size with the first 32 bits consistent and the next 32 bits either split evenly into 2 sections or 1 completely unused section. This allows us to congregate the 2 structures into one general structure.

In the assignment we had some struggle understanding when ARP lookups needed to be done because of the fact that ICMP messages and ARP packets have already the interfaces the original packet arrived on and to simply switch the source and destinations easier and quicker than looking up the ARPCache on every instance. It was decided that it needed to lookup for the sake of completing the assignment as the solution does, we decided to perform the lookup regardless.
