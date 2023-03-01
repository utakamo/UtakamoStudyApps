/* duckdump.h */
/* libpcapには予めプロトコルの定義（netinet/ether.hなど）が存在しますが今回は使用しません。 */
/* パケット構造を理解することも目的に含め、今回は以下のように自作しています。 */
#ifndef _DUCKDUMP_H
#define _DUCKDUMP_H

#define INTERNET_PROTOCOL_VERSION_4 0x0800

/*******************************/
/*  Address Structure Define   */
/*******************************/

/* Macアドレス */
typedef struct mac_address 
{
	/* TOTAL SIZE = 6byte [48bit] */
	unsigned char octet1;
	unsigned char octet2;
	unsigned char octet3;
	unsigned char octet4;
	unsigned char octet5;
	unsigned char octet6;  
} mac_address;

/* IPv4アドレス */
typedef struct ipv4_address 
{
	/* TOTAL SIZE = 4byte [32bit] */
	unsigned char octet1;
	unsigned char octet2;
	unsigned char octet3;
	unsigned char octet4;
} ipv4_address;

/****************************/
/*  Protocol Packet Define  */
/****************************/

/* Internet Protocol Version 4 [IPv4] */
/* 1byte未満のデータはビットフィールドで指定しています。 */
/* ビットフィールドは「型 変数名 : ビット数」で指定可能です。*/
typedef struct ipv4 
{
	/* IPv4 Header #3 */
	unsigned char version : 4;      /* #3-1 */
	unsigned char ihl : 4;          /* #3-2 */
	unsigned char type_of_service;  /* #3-3 */
	ushort total_length;            /* #3-4 */
	ushort identification;          /* #3-5 */
	ushort flags : 3;               /* #3-6 */
	ushort offset_flagment : 13;    /* #3-7 */
	unsigned char time_of_live;     /* #3-8 */
	unsigned char upper_protocol;   /* #3-9 */
	ushort header_checksum;         /* #3-10 */
	ipv4_address src_ip_addr;       /* #3-11*/
	ipv4_address dst_ip_addr;       /* #3-12 */

	/* IPv4 ペイロード部 #4 */
	/* 今回は抽出しないので未定義 */
} ipv4;

/* Ethernetフレーム */
typedef struct ethernet 
{
	/* Ethernet ヘッダー部 #1 */
	mac_address dst_mac_addr;  /* #1-1 */
	mac_address src_mac_addr;   /* #1-2 */
	ushort upper_protocol_type; /* #1-3 */

	/* Ethernet ペイロード部 #2 */
	ipv4 payload;   /* #3 & #4 */
} ethernet;

#endif
