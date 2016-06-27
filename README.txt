READ ME
_______________________________

Author: Kendall Weihe
Project name: Simple IP forwarding

To run the program run:
  - make clean
  - make
  - ./ip_forward ip_packets routing_table.txt

To test:
  - ./ip_forward ip_packet_out routing_table.txt
  - verify values from initial run

Purpose:
  Routers are used for forwarding packets from a previous hop to a next hop
  They accomplish this function via an IP forwarding program
    this program is a slightly simplified version
  The general process consists of
    - read in ip_packets binary file and a txt file consisting of the routing table
      - the routing table consists of three columns
        - column 1 is the NetID column
          - this IP address covers a set of IP addresses handled by the nexthop
        - column 2 is the Mask
          - this IP address is in a form such as 255.255.0.0 where this value is logically AND'ed
            with the destination IP address specified in the IP packet, and the result should match
            at least one of the NetID's
        - column 3 is the NextHop -- this is the IP address of the next router the packet
          should be sent to
    - read each header field into structs consisting of data structures of the same size as each field
      - for example, a 1 byte field should read into a char variable
      - note that anything other than a char needs to be reordered from network to host order
    - splice or concatenate all headers into 16-bit blocks then sum
      - after summing take the one's complement
      - the value should be zero
      - if the value is not zero, than the checksum header has detected an error in the packet
      - if error, then drop packet
    - if checksum verification passes, decrement the TTL header field
      - if the new TTL value = 0, then drop packet
    - if TTL verification passes, then recompute checksum value (taking decremented TTL into account)
    - read in data field
    - write headers and data to binary ip_packet output file
      - ensure that the ordering is correct
      - testing can be completed by using the output value as the input to the program and verifying values

The limitations of this program:
  - fragmentation is not taken into account
  - flag bits are not taken into account

There are no prevalent bugs in this program
