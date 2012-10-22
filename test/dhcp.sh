#!/bin/sh
cd ..
echo DHCP-Discover
./tool_DHCP_decode.py 0101060029104a2e0004800000000000000000000000000000000000002128104a2e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363350101371801020305060b0c0d0f1011122b363c438081828384858687390204ec611100000000003030323132383130344132455d0200005e030102013c20505845436c69656e743a417263683a30303030303a554e44493a303032303031ff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
read a
echo DHCP-Offer
./tool_DHCP_decode.py 0201060029104a2e0004800000000000ac1f7080ac1f702100000000002128104a2e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c696e75782d696e7374616c6c2f7078656c696e75782e300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604ac1f702133040000a8c00104fffffc000c0d7376723130312e6c61622e6f730f066c61622e6f73ff000000000000000000000000000000
read a
echo DHCP-Request
./tool_DHCP_decode.py 0101060029104a2e0004800000000000000000000000000000000000002128104a2e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501033204ac1f7080371801020305060b0c0d0f1011122b363c438081828384858687390204ec3604ac1f7021611100000000003030323132383130344132455d0200005e030102013c20505845436c69656e743a417263683a30303030303a554e44493a303032303031ff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
read a
echo DHCP-ACK
./tool_DHCP_decode.py 0201060029104a2e0004800000000000ac1f7080ac1f702100000000002128104a2e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c696e75782d696e7374616c6c2f7078656c696e75782e300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501053604ac1f702133040000a8c00104fffffc000c0d7376723130312e6c61622e6f730f066c61622e6f73ff000000000000000000000000000000
read a
echo DHCP-Discover
./tool_DHCP_decode.py 010106003f7d16640000000000000000000000000000000000000000002128104a2e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000063825363350101370d011c02790f060c28292a1a77033c2b616e61636f6e64612d4c696e757820322e362e33322d3232302e656c362e7838365f3634207838365f3634ff
read a
echo DHCP-Offer
./tool_DHCP_decode.py 020106003f7d16640000000000000000ac1f7080ac1f702100000000002128104a2e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c696e75782d696e7374616c6c2f7078656c696e75782e300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604ac1f702133040000a8c00104fffffc000f066c61622e6f730c0d7376723130312e6c61622e6f73ff000000000000000000000000000000
read a
echo DHCP-Request
./tool_DHCP_decode.py 010106003f7d16640000000000000000000000000000000000000000002128104a2e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501033604ac1f70213204ac1f7080370d011c02790f060c28292a1a77033c2b616e61636f6e64612d4c696e757820322e362e33322d3232302e656c362e7838365f3634207838365f3634ff
read a
echo DHCP-ACK
./tool_DHCP_decode.py 020106003f7d16640000000000000000ac1f7080ac1f702100000000002128104a2e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c696e75782d696e7374616c6c2f7078656c696e75782e300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501053604ac1f702133040000a8c00104fffffc000f066c61622e6f730c0d7376723130312e6c61622e6f73ff000000000000000000000000000000

