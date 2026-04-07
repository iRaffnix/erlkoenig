%% Kernel/netlink constants for nf_tables.
%%
%% Consolidates all constants from linux/netfilter/nf_tables.h,
%% linux/netfilter.h, and linux/netlink.h into a single header.
%% Source modules include this instead of defining their own copies.
%%
%% Generated expression modules (src/gen/*_gen.erl) keep their own
%% local defines since they are produced by nft_gen.escript.

-ifndef(NFT_CONSTANTS_HRL).
-define(NFT_CONSTANTS_HRL, true).

%% ===================================================================
%% Netlink flags (linux/netlink.h)
%% ===================================================================

-define(NLM_F_REQUEST, 16#0001).
-define(NLM_F_ACK, 16#0004).
-define(NLM_F_DUMP, 16#0300).
-define(NLM_F_CREATE, 16#0400).
-define(NLM_F_APPEND, 16#0800).

-define(NLMSG_DONE, 3).

%% ===================================================================
%% Netfilter netlink (linux/netfilter/nfnetlink.h)
%% ===================================================================

-define(NLMSGHDR_SIZE, 16).
-define(NFGENMSG_SIZE, 4).
-define(NFNETLINK_V0, 0).

-define(NFNL_SUBSYS_NONE, 0).
-define(NFNL_SUBSYS_CTNETLINK, 1).
-define(NFNL_SUBSYS_ULOG, 4).
-define(NFNL_SUBSYS_NFTABLES, 10).

-define(NFNL_MSG_BATCH_BEGIN, 16).
-define(NFNL_MSG_BATCH_END, 17).

%% ===================================================================
%% Address families (linux/netfilter.h)
%% ===================================================================

-define(NFPROTO_INET, 1).
-define(NFPROTO_IPV4, 2).
-define(NFPROTO_IPV6, 10).

%% ===================================================================
%% Netfilter verdicts (linux/netfilter.h, stable ABI)
%% ===================================================================

-define(NF_DROP, 0).
-define(NF_ACCEPT, 1).

%% ===================================================================
%% Netfilter hooks (linux/netfilter.h)
%% ===================================================================

-define(NF_INET_PRE_ROUTING, 0).
-define(NF_INET_LOCAL_IN, 1).
-define(NF_INET_FORWARD, 2).
-define(NF_INET_LOCAL_OUT, 3).
-define(NF_INET_POST_ROUTING, 4).
-define(NF_NETDEV_INGRESS, 0).

%% ===================================================================
%% Conntrack multicast groups
%% ===================================================================

-define(NFNLGRP_CONNTRACK_NEW, 1).
-define(NFNLGRP_CONNTRACK_UPDATE, 2).
-define(NFNLGRP_CONNTRACK_DESTROY, 3).

%% ===================================================================
%% NFLOG constants (linux/netfilter/nfnetlink_log.h)
%% ===================================================================

-define(NFULNL_MSG_PACKET, 0).
-define(NFULNL_MSG_CONFIG, 1).

-define(NFULNL_CFG_CMD_BIND, 1).
-define(NFULNL_CFG_CMD_PF_BIND, 3).

-define(NFULNL_COPY_PACKET, 16#02).

-define(NFULA_CFG_CMD, 1).
-define(NFULA_CFG_MODE, 2).
-define(NFULA_PACKET_HDR, 1).
-define(NFULA_IFINDEX_INDEV, 4).
-define(NFULA_PAYLOAD, 9).
-define(NFULA_PREFIX, 10).

%% ===================================================================
%% nft_registers
%% ===================================================================

-define(NFT_REG_VERDICT, 0).
-define(NFT_REG_1, 1).
-define(NFT_REG_2, 2).
-define(NFT_REG_3, 3).
-define(NFT_REG_4, 4).
-define(NFT_REG32_00, 8).
-define(NFT_REG32_01, 9).
-define(NFT_REG32_02, 10).
-define(NFT_REG32_03, 11).
-define(NFT_REG32_04, 12).
-define(NFT_REG32_05, 13).
-define(NFT_REG32_06, 14).
-define(NFT_REG32_07, 15).
-define(NFT_REG32_08, 16).
-define(NFT_REG32_09, 17).
-define(NFT_REG32_10, 18).
-define(NFT_REG32_11, 19).
-define(NFT_REG32_12, 20).
-define(NFT_REG32_13, 21).
-define(NFT_REG32_14, 22).
-define(NFT_REG32_15, 23).

%% ===================================================================
%% nft_verdicts
%% ===================================================================

-define(NFT_CONTINUE, 16#FFFFFFFF).
-define(NFT_BREAK, 16#FFFFFFFE).
-define(NFT_JUMP, 16#FFFFFFFD).
-define(NFT_GOTO, 16#FFFFFFFC).
-define(NFT_RETURN, 16#FFFFFFFB).

%% ===================================================================
%% NFT_MSG_* message types (nf_tables_msg_types enum)
%% ===================================================================

-define(NFT_MSG_NEWTABLE, 0).
-define(NFT_MSG_GETTABLE, 1).
-define(NFT_MSG_DELTABLE, 2).
-define(NFT_MSG_NEWCHAIN, 3).
-define(NFT_MSG_GETCHAIN, 4).
-define(NFT_MSG_DELCHAIN, 5).
-define(NFT_MSG_NEWRULE, 6).
-define(NFT_MSG_GETRULE, 7).
-define(NFT_MSG_DELRULE, 8).
-define(NFT_MSG_NEWSET, 9).
-define(NFT_MSG_GETSET, 10).
-define(NFT_MSG_DELSET, 11).
-define(NFT_MSG_NEWSETELEM, 12).
-define(NFT_MSG_GETSETELEM, 13).
-define(NFT_MSG_DELSETELEM, 14).
-define(NFT_MSG_NEWGEN, 15).
-define(NFT_MSG_GETGEN, 16).
-define(NFT_MSG_NEWOBJ, 18).
-define(NFT_MSG_GETOBJ, 19).
-define(NFT_MSG_DELOBJ, 20).
-define(NFT_MSG_GETOBJ_RESET, 21).
-define(NFT_MSG_NEWFLOWTABLE, 16#16).

%% ===================================================================
%% NFTA_LIST_* (generic nesting)
%% ===================================================================

-define(NFTA_LIST_ELEM, 1).

%% ===================================================================
%% NFTA_DATA_* / NFTA_VERDICT_*
%% ===================================================================

-define(NFTA_DATA_VALUE, 1).
-define(NFTA_DATA_VERDICT, 2).

-define(NFTA_VERDICT_CODE, 1).
-define(NFTA_VERDICT_CHAIN, 2).

-define(NFT_DATA_VERDICT, 16#FFFFFF00).

%% ===================================================================
%% NFTA_EXPR_*
%% ===================================================================

-define(NFTA_EXPR_NAME, 1).
-define(NFTA_EXPR_DATA, 2).

%% ===================================================================
%% NFTA_TABLE_*
%% ===================================================================

-define(NFTA_TABLE_NAME, 1).
-define(NFTA_TABLE_FLAGS, 2).

%% ===================================================================
%% NFTA_CHAIN_* / NFTA_HOOK_*
%% ===================================================================

-define(NFTA_CHAIN_TABLE, 1).
-define(NFTA_CHAIN_NAME, 3).
-define(NFTA_CHAIN_HOOK, 4).
-define(NFTA_CHAIN_POLICY, 5).
-define(NFTA_CHAIN_TYPE, 7).

-define(NFTA_HOOK_HOOKNUM, 1).
-define(NFTA_HOOK_PRIORITY, 2).

%% ===================================================================
%% NFTA_RULE_*
%% ===================================================================

-define(NFTA_RULE_TABLE, 1).
-define(NFTA_RULE_CHAIN, 2).
-define(NFTA_RULE_HANDLE, 3).
-define(NFTA_RULE_EXPRESSIONS, 4).

%% ===================================================================
%% NFTA_SET_* (set attributes)
%% ===================================================================

-define(NFTA_SET_TABLE, 1).
-define(NFTA_SET_NAME, 2).
-define(NFTA_SET_FLAGS, 3).
-define(NFTA_SET_KEY_TYPE, 4).
-define(NFTA_SET_KEY_LEN, 5).
-define(NFTA_SET_DATA_TYPE, 6).
-define(NFTA_SET_DATA_LEN, 7).
-define(NFTA_SET_POLICY, 8).
-define(NFTA_SET_DESC, 9).
-define(NFTA_SET_ID, 10).
-define(NFTA_SET_TIMEOUT, 11).

%% Descriptor sub-attributes (nested inside NFTA_SET_DESC)
-define(NFTA_SET_DESC_SIZE, 1).
-define(NFTA_SET_DESC_CONCAT, 2).

%% Field descriptor attributes (nested inside NFTA_SET_DESC_CONCAT)
-define(NFTA_SET_FIELD_LEN, 1).

%% Set flags
-define(NFT_SET_ANONYMOUS, 16#01).
-define(NFT_SET_CONSTANT, 16#02).
-define(NFT_SET_INTERVAL, 16#04).
-define(NFT_SET_MAP, 16#08).
-define(NFT_SET_TIMEOUT, 16#10).
-define(NFT_SET_EVAL, 16#20).
-define(NFT_SET_CONCAT, 16#40).

%% ===================================================================
%% NFTA_SET_ELEM_* (set element attributes)
%% ===================================================================

-define(NFTA_SET_ELEM_LIST_TABLE, 1).
-define(NFTA_SET_ELEM_LIST_SET, 2).
-define(NFTA_SET_ELEM_LIST_ELEMENTS, 3).
-define(NFTA_SET_ELEM_LIST_SET_ID, 4).

-define(NFTA_SET_ELEM_KEY, 1).
-define(NFTA_SET_ELEM_DATA, 2).
-define(NFTA_SET_ELEM_TIMEOUT, 4).

%% ===================================================================
%% NFTA_OBJ_*
%% ===================================================================

-define(NFTA_OBJ_TABLE, 1).
-define(NFTA_OBJ_NAME, 2).
-define(NFTA_OBJ_TYPE, 3).
-define(NFTA_OBJ_DATA, 4).

%% ===================================================================
%% NFTA_FLOWTABLE_*
%% ===================================================================

-define(NFTA_FLOWTABLE_TABLE, 1).
-define(NFTA_FLOWTABLE_NAME, 2).
-define(NFTA_FLOWTABLE_HOOK, 3).
-define(NFTA_FLOWTABLE_DEVS, 4).
-define(NFTA_FLOWTABLE_FLAGS, 6).

-define(NFTA_FLOWTABLE_HOOK_NUM, 1).
-define(NFTA_FLOWTABLE_HOOK_PRIORITY, 2).

-define(NFTA_DEVICE_NAME, 1).

%% ===================================================================
%% Expression-specific NFTA_* attributes (hand-written modules)
%% ===================================================================

%% --- immediate ---
-define(NFTA_IMMEDIATE_DREG, 1).
-define(NFTA_IMMEDIATE_DATA, 2).

%% --- cmp ---
-define(NFTA_CMP_SREG, 1).
-define(NFTA_CMP_OP, 2).
-define(NFTA_CMP_DATA, 3).

%% --- payload ---
-define(NFTA_PAYLOAD_DREG, 1).
-define(NFTA_PAYLOAD_BASE, 2).
-define(NFTA_PAYLOAD_OFFSET, 3).
-define(NFTA_PAYLOAD_LEN, 4).

%% --- meta ---
-define(NFTA_META_DREG, 1).
-define(NFTA_META_KEY, 2).

%% --- ct ---
-define(NFTA_CT_DREG, 1).
-define(NFTA_CT_KEY, 2).

%% --- bitwise ---
-define(NFTA_BITWISE_SREG, 1).
-define(NFTA_BITWISE_DREG, 2).
-define(NFTA_BITWISE_LEN, 3).
-define(NFTA_BITWISE_MASK, 4).
-define(NFTA_BITWISE_XOR, 5).

%% --- counter ---
-define(NFTA_COUNTER_BYTES, 1).
-define(NFTA_COUNTER_PACKETS, 2).

%% --- log ---
-define(NFTA_LOG_GROUP, 1).
-define(NFTA_LOG_PREFIX, 2).
-define(NFTA_LOG_SNAPLEN, 3).
-define(NFTA_LOG_QTHRESHOLD, 4).
-define(NFTA_LOG_LEVEL, 5).
-define(NFTA_LOG_FLAGS, 6).

%% --- limit ---
-define(NFTA_LIMIT_RATE, 1).
-define(NFTA_LIMIT_UNIT, 2).
-define(NFTA_LIMIT_BURST, 3).
-define(NFTA_LIMIT_TYPE, 4).
-define(NFTA_LIMIT_FLAGS, 5).

%% --- lookup ---
-define(NFTA_LOOKUP_SET, 1).
-define(NFTA_LOOKUP_SREG, 2).
-define(NFTA_LOOKUP_SET_ID, 4).
-define(NFTA_LOOKUP_FLAGS, 5).

%% --- objref ---
-define(NFTA_OBJREF_IMM_TYPE, 1).
-define(NFTA_OBJREF_IMM_NAME, 2).

%% --- quota ---
-define(NFTA_QUOTA_BYTES, 1).
-define(NFTA_QUOTA_FLAGS, 2).

%% ===================================================================
%% nft_cmp_ops
%% ===================================================================

-define(NFT_CMP_EQ, 0).
-define(NFT_CMP_NEQ, 1).
-define(NFT_CMP_LT, 2).
-define(NFT_CMP_LTE, 3).
-define(NFT_CMP_GT, 4).
-define(NFT_CMP_GTE, 5).

%% ===================================================================
%% nft_range_ops
%% ===================================================================

-define(NFT_RANGE_EQ, 0).
-define(NFT_RANGE_NEQ, 1).

%% ===================================================================
%% nft_lookup_flags
%% ===================================================================

-define(NFT_LOOKUP_F_INV, 1).

%% ===================================================================
%% nft_payload_bases
%% ===================================================================

-define(NFT_PAYLOAD_LL_HEADER, 0).
-define(NFT_PAYLOAD_NETWORK_HEADER, 1).
-define(NFT_PAYLOAD_TRANSPORT_HEADER, 2).
-define(NFT_PAYLOAD_INNER_HEADER, 3).
-define(NFT_PAYLOAD_TUN_HEADER, 4).

%% ===================================================================
%% nft_meta_keys
%% ===================================================================

-define(NFT_META_LEN, 0).
-define(NFT_META_PROTOCOL, 1).
-define(NFT_META_PRIORITY, 2).
-define(NFT_META_MARK, 3).
-define(NFT_META_IIF, 4).
-define(NFT_META_OIF, 5).
-define(NFT_META_IIFNAME, 6).
-define(NFT_META_OIFNAME, 7).
-define(NFT_META_IFTYPE, 8).
-define(NFT_META_OIFTYPE, 9).
-define(NFT_META_SKUID, 10).
-define(NFT_META_SKGID, 11).
-define(NFT_META_NFTRACE, 12).
-define(NFT_META_RTCLASSID, 13).
-define(NFT_META_SECMARK, 14).
-define(NFT_META_NFPROTO, 15).
-define(NFT_META_L4PROTO, 16).
-define(NFT_META_BRI_IIFNAME, 17).
-define(NFT_META_BRI_OIFNAME, 18).
-define(NFT_META_PKTTYPE, 19).
-define(NFT_META_CPU, 20).
-define(NFT_META_IIFGROUP, 21).
-define(NFT_META_OIFGROUP, 22).
-define(NFT_META_CGROUP, 23).
-define(NFT_META_PRANDOM, 24).
-define(NFT_META_SECPATH, 25).
-define(NFT_META_IIFKIND, 26).
-define(NFT_META_OIFKIND, 27).
-define(NFT_META_BRI_IIFPVID, 28).
-define(NFT_META_BRI_IIFVPROTO, 29).
-define(NFT_META_TIME_NS, 30).
-define(NFT_META_TIME_DAY, 31).
-define(NFT_META_TIME_HOUR, 32).
-define(NFT_META_SDIF, 33).
-define(NFT_META_SDIFNAME, 34).
-define(NFT_META_BRI_BROUTE, 35).
-define(NFT_META_BRI_IIFHWADDR, 36).

%% ===================================================================
%% nft_ct_keys
%% ===================================================================

-define(NFT_CT_STATE, 0).
-define(NFT_CT_DIRECTION, 1).
-define(NFT_CT_STATUS, 2).
-define(NFT_CT_MARK, 3).
-define(NFT_CT_SECMARK, 4).
-define(NFT_CT_EXPIRATION, 5).
-define(NFT_CT_HELPER, 6).
-define(NFT_CT_L3PROTOCOL, 7).
-define(NFT_CT_SRC, 8).
-define(NFT_CT_DST, 9).
-define(NFT_CT_PROTOCOL, 10).
-define(NFT_CT_PROTO_SRC, 11).
-define(NFT_CT_PROTO_DST, 12).
-define(NFT_CT_LABELS, 13).
-define(NFT_CT_PKTS, 14).
-define(NFT_CT_BYTES, 15).
-define(NFT_CT_AVGPKT, 16).
-define(NFT_CT_ZONE, 17).
-define(NFT_CT_EVENTMASK, 18).
-define(NFT_CT_SRC_IP, 19).
-define(NFT_CT_DST_IP, 20).
-define(NFT_CT_SRC_IP6, 21).
-define(NFT_CT_DST_IP6, 22).
-define(NFT_CT_ID, 23).

%% ===================================================================
%% nft_limit
%% ===================================================================

-define(NFT_LIMIT_PKTS, 0).
-define(NFT_LIMIT_PKT_BYTES, 1).
-define(NFT_LIMIT_F_INV, 1).

%% ===================================================================
%% nft_reject
%% ===================================================================

-define(NFT_REJECT_ICMP_UNREACH, 0).
-define(NFT_REJECT_TCP_RST, 1).
-define(NFT_REJECT_ICMPX_UNREACH, 2).

-define(NFT_REJECT_ICMPX_NO_ROUTE, 0).
-define(NFT_REJECT_ICMPX_PORT_UNREACH, 1).
-define(NFT_REJECT_ICMPX_HOST_UNREACH, 2).
-define(NFT_REJECT_ICMPX_ADMIN_PROHIBITED, 3).

%% ===================================================================
%% nft_nat
%% ===================================================================

-define(NFT_NAT_SNAT, 0).
-define(NFT_NAT_DNAT, 1).

%% ===================================================================
%% Object types (nf_tables.h #defines)
%% ===================================================================

-define(NFT_OBJECT_COUNTER, 1).
-define(NFT_OBJECT_QUOTA, 2).
-define(NFT_OBJECT_CT_HELPER, 3).
-define(NFT_OBJECT_LIMIT, 4).
-define(NFT_OBJECT_CONNLIMIT, 5).
-define(NFT_OBJECT_TUNNEL, 6).
-define(NFT_OBJECT_CT_TIMEOUT, 7).
-define(NFT_OBJECT_SECMARK, 8).
-define(NFT_OBJECT_CT_EXPECT, 9).
-define(NFT_OBJECT_SYNPROXY, 10).

%% NFT_CONSTANTS_HRL
-endif.
