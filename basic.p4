/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
/**
*/
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
const bit<48> DEFAULT_SWITCH_MAC = 0x112233445566; // Replace with actual MAC address

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
    ethernet_t ethernet;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

// Define switch MAC address with default value
bit<48> switch_mac_address = DEFAULT_SWITCH_MAC;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* DONE: add parser logic */

        // Parse the Ethernet header from the packet_in input parameter into the hdr.ethernet header.
        packet.extract(hdr.ethernet);
        // Set the corresponding fields in the meta.ethernet metadata using the values extracted from the Ethernet header.
        meta.ethernet.dstAddr = hdr.ethernet.dstAddr;
        meta.ethernet.srcAddr = hdr.ethernet.srcAddr;
        meta.ethernet.etherType = hdr.ethernet.etherType;

        // 2: Decrement ttl
        // 2: Check packet is an IPv4 packet
        if (hdr.ethernet.etherType == 0x0800) {
            // Extract the IPv4 header fields from the packet and store them in the hdr.ipv4 struct. This makes the IPv4 header fields available for processing in the P4 program.
            extract(hdr.ipv4);
        }

        // Transition to the accept state to indicate that the parser has successfully parsed the Ethernet header.
        transition accept;
    }
    
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }
    
    /* DONE: fill out code in action body*/
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        // i. Set the egress port for the next hop
        modify_field(standard_metadata.egress_spec, port);

        // ii. Update the Ethernet destination address with the address of the next hop.
        modify_field(hdr.ethernet.dstAddr, dstAddr);

        // iii. Update the ethernet source address with the address of the switch
        modify_field(hdr.ethernet.srcAddr, switch_mac_address); // :Q switch_mac_address ?


         // iv: Decrements the ttl field in the IPv4 header by 1. 
         // Check if TTL is greater than 0
         if (hdr.ipv4.ttl > 0) {
            // Decrement TTL by 1
            hdr.ipv4.ttl -= 1;
         } else {
            // Drop packet if TTL is 0
            drop();
         }
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    /* Forward the packet */
    apply {
        /* DONE: fix ingress control logic
         *  - ipv4_lpm should be applied only when IPv4 header is valid
         *
         */

        if (hdr.ipv4.isValid() && hdr.ipv4.protocol == TYPE_IPV4) { // OR hdr.ethernet.etherType == 0x0800
            ipv4_lpm.apply();
        } else {
        }
    }
    drop();
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {

    // Define the order in which fields are inserted into the outgoing packet

    apply {
        /* DONE: add deparser logic */
        packet.emit(hdr.ethernet);
        if (hdr.ipv4.isValid()) {
            packet.emit(hdr.ipv4);
        }

        // // OR 
        // // Deparse Ethernet header
        // deparse(hdr.ethernet);
        // // Deparse IPv4 header
        // if (hdr.ipv4.isValid()) {
        //     deparse(hdr.ipv4);
        // }
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
