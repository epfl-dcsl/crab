/* -*- P4_14 -*- */

#ifdef __TARGET_TOFINO__
#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/stateful_alu_blackbox.p4>
#else
#error This program is intended to compile for Tofino P4 architecture only
#endif

#include "conf.h"

#define _parser_counter_ ig_prsr_ctrl.parser_counter

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
header_type ethernet_t {
	fields {
        dstAddr   : 48;
        srcAddr   : 48;
        etherType : 16;
	}
}

header_type arp_t {
	fields {
		hwType       : 16;
		protoType    : 16;
		hwAddrLen    : 8;
		protoAddrLen : 8;
		opcode       : 16;
		srcHwAddr    : 48;
		srcProtoAddr : 32;
		dstHwAddr    : 48;
		dstProtoAddr : 32;
	}
}

header_type ipv4_t {
	fields {
		version        : 4;
		ihl            : 4;
		diffserv       : 8;
		totalLen       : 16;
		identification : 16;
		flags          : 3;
		fragOffset     : 13;
		ttl            : 8;
		protocol       : 8;
		hdrChecksum    : 16;
		srcAddr        : 32;
		dstAddr        : 32;
	}
}

header_type tcp_t {
	fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
	}
}

header_type redir_info_t {
	fields {
		type_f: 8;
		len_f: 8;
		ip_f: 32;
		nop_f: 16;
	}
}

/*************************************************************************
 ***********************  M E T A D A T A  *******************************
 *************************************************************************/
header_type md_t {
	fields {
        len : 16;
	}
}


/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
header ethernet_t ethernet;
header arp_t arp;
header ipv4_t ipv4;
header tcp_t tcp;
header redir_info_t redir_info;

metadata md_t md;

parser start {
	extract(ethernet);
	return select(latest.etherType) {
		0x0800: parse_ip;
		0x0806: parse_arp;
		default: ingress;
	}
}

parser parse_arp {
	extract(arp);
	return ingress;
}

parser parse_ip {
	extract(ipv4);
    set_metadata(md.len, latest.totalLen);
	return select(latest.protocol) {
		0x06: parse_tcp;
		default: ingress;
	}
}

parser parse_tcp {
	extract(tcp);
	return select(current(0, 8)) {
		REDIR_OPT : parse_redir_opt;
		default: ingress;
	}
}

parser parse_redir_opt {
	extract(redir_info);
	return ingress;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control ingress {
	if (valid(arp))
		process_arp();
	else if (valid(tcp)) {
		process_tcp();
	}
	else
		apply(tbl_drop);

}

control process_arp {
	if (arp.dstProtoAddr == ROUTER_IP)
		apply(tbl_tx_arp_reply);
	else
		apply(tbl_drop);
}

control process_tcp {
	// handle only SYN packets
	if (tcp.ctrl == 0x2) {
		apply(tbl_lb_syn);
		apply(tbl_add_redir_opt);
	}
	else
		apply(tbl_drop);
}

table tbl_tx_arp_reply {
	actions { tx_arp_reply;   }
	default_action : tx_arp_reply();
	size : 1;
}

action tx_arp_reply() {
	modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);

	modify_field(ethernet.dstAddr, ethernet.srcAddr);
	modify_field(ethernet.srcAddr, ROUTER_MAC);

	modify_field(arp.opcode, 2);
	modify_field(arp.dstHwAddr, arp.srcHwAddr);
	modify_field(arp.dstProtoAddr, arp.srcProtoAddr);
	modify_field(arp.srcHwAddr, ROUTER_MAC);
	modify_field(arp.srcProtoAddr, ROUTER_IP);
}

table tbl_drop {
	actions { act_drop;  }
	default_action : act_drop();
	size : 1;
}

action act_drop() {
	drop();
	exit();
}

table tbl_lb_syn {
	actions { act_lb_syn;  }
	default_action : act_lb_syn();
	size : 1;
}

action act_lb_syn() {
	modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);

	modify_field(ethernet.dstAddr, TARGET_MAC);
	modify_field(ethernet.srcAddr, ROUTER_MAC);
	modify_field(ipv4.dstAddr, TARGET_IP);
}

table tbl_add_redir_opt {
	actions { act_add_redir_opt;  }
	default_action : act_add_redir_opt();
	size : 1;
}

action act_add_redir_opt() {
	add_to_field(tcp.dataOffset, 2);
	add_header(redir_info);
	modify_field(redir_info.type_f, REDIR_OPT);
	modify_field(redir_info.len_f, 6);
	modify_field(redir_info.ip_f, ROUTER_IP);
	modify_field(redir_info.nop_f, 0x101);
	add_to_field(ipv4.totalLen, 8);
}

field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input        { ipv4_checksum_list;   }
    algorithm    : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    update ipv4_checksum;
}

field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
		ipv4.totalLen;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.ecn;
        tcp.ctrl;
        tcp.window;
        tcp.urgentPtr;
		redir_info.type_f;
		redir_info.len_f;
		redir_info.ip_f;
		redir_info.nop_f;
        payload;
}

field_list_calculation tcp_checksum {
	input {
        tcp_checksum_list;
	}
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    update tcp_checksum;
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
