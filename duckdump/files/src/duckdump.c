/* duckdump.c */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>
#include <pcap.h>  /* libpcapのヘッダーファイル */
#include "duckdump.h"

#define MAX_LINE_FOR_OUTPUTFILE	100

/* PROTOTYPE DECLARATION */
void output_logfile(FILE *fp, const u_char *raw_data, struct tm *localtime);

/* GLOBAL VARIABLE DECLARATION */
bool terminate_flg = false;

static void create_daemon()
{
	pid_t pid;

	pid = fork();

 	if (pid < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	if (setsid() < 0)
		exit(EXIT_FAILURE);

	signal(SIGCHLD, SIG_IGN);

	signal(SIGHUP, SIG_IGN);

	pid = fork();

	if (pid < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	umask(0);

	chdir("/");

	int x;
	for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
	{
		close(x);
	}
}

void sigterm_handler(int signum)
{
	terminate_flg = true;
}

int main(int argc, char** argv)
{
	create_daemon();

	FILE *fp;
	pcap_t *pcap_handle = NULL;
	pcap_if_t *ift = NULL;
	struct pcap_pkthdr header;
	const u_char *raw_data;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct stat st = {0};

	/* シグナルハンドラ登録 killコマンドによるプロセス終了時にsigterm_handler関数を呼び出す */
	signal(SIGTERM, sigterm_handler);

	/* tmpfファイルシステム上にduckdumpディレクトリがなければ作成 */
	if (stat("/tmp/duckdump", &st) == -1)
		mkdir("/tmp/duckdump", 0777);

	/* 一時ファイルcap.logを書き込みモードでオープン */
	if((fp = fopen("/tmp/duckdump/cap.log", "w")) == NULL)
	{
		return EXIT_FAILURE;
	}

	/* 引数として何も指定していなかった場合は終了（cap.logには使用可能なNIC一覧が出力されている） */
	if(argv[1] == NULL)
	{
		fprintf(fp, "please specify target nic. (ex eth0, wlan0\n");
		fclose(fp);
		return EXIT_FAILURE;
	}

	bool exist_nic = false;

	/* システムが管理するNIC情報を取得 */
	if(pcap_findalldevs(&ift, errbuf) == 0) {
		pcap_if_t *it = ift;

		fprintf(fp, "NIC LIST\n");

		while (it)
		{
			fprintf(fp, "Device: %s - %s\n", it->name, it->description);

			if(strcmp(argv[1], it->name) == 0)
				exist_nic = true;

			it = it->next;
		}
		pcap_freealldevs(ift);
	}
	else {
		fprintf(fp, "error: %s\n", errbuf);
		fclose(fp);
		return EXIT_FAILURE;
	}

	/* 引数で指定したNICと一致するものがなかった場合は終了 */
	if(exist_nic == false)
	{
		fprintf(fp, "Target NIC not found.\n");
		fclose(fp);
		return EXIT_FAILURE;
	}

	/* パケットキャプチャハンドルを取得します。これはパケットキャプチャ処理の前準備です。 */
	/* インタフェースの起動に最大30秒待ちます。 */
	for (int retry = 0; retry < 5; retry++)
	{
		pcap_handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

		if (pcap_handle != NULL)
			break;

		sleep(6);
	}

	if (pcap_handle == NULL)
	{
		fprintf(fp, "Couldn't open device %s: %s\n", argv[1], errbuf);
		fclose(fp);
		return EXIT_FAILURE;
	}

	time_t current_raw_time;
	struct tm localtime;
	int line_num = 0;

	/* パケットキャプチャのメイン処理 */
	for (;;)
	{
		current_raw_time = time(NULL);
		localtime_r(&current_raw_time, &localtime);

		/* 一時ファイルに最大100個のパケットログを出力します */
		/* 上限に達すると、出力位置を先頭行に戻して出力を続けます */
		if(line_num >= MAX_LINE_FOR_OUTPUTFILE)
		{
		    //fseek(fp, 0L, SEEK_SET);
		    if (freopen("/tmp/duckdump/cap.log", "w", fp) == NULL)
		    	return EXIT_FAILURE;

		    line_num = 0;
		}

		/* パケットキャプチャにより、EthernetフレームのRAWデータを取得します */
		raw_data = pcap_next(pcap_handle, &header);

		if(raw_data != NULL)
		{
			/* キャプチャ情報を一時ファイルに出力します */
			output_logfile(fp, raw_data, &localtime);
		}

		/* killコマンドによってSIGTERMシグナルが通知されたときに、フラグが立ちます */
		/* パケットキャプチャループを抜け、終了処理に移行します */
		if(terminate_flg == true)
		{
			fprintf(fp, "This program is terminated.");
			break;
		}

		line_num++;
	}

	/* プロセス終了時の後処理 */
	pcap_close(pcap_handle);
	fclose(fp);
	return EXIT_SUCCESS;
}

//EthernetフレームのRAWデータにEthernetヘッダーとIPv4ヘッダ―定義をマッピングします。
//これにより、ヘッダー情報を明示的に抽出（取得）することが可能です。
//得られたIPv4アドレスとMACアドレスは/tmp/duckdump/cap.logに記録されます。
void output_logfile(FILE *fp, const u_char* raw_data, struct tm *localtime)
{
	ethernet *frame = (ethernet*)raw_data; //Ethernetヘッダー定義を被せます（マッピング）。
	ipv4 *packet = &(frame->payload); //Ethernetペイロードの先頭からIPv4ヘッダー定義を被せます。
	//ポイント：IPv4アドレス指定が長くなるのでIPv4ヘッダー構造体をさらに被せています。

	//ガード処理
	//EthernetのタイプフィールドがIPv4(0x0800)以外のものは、ここで終了（キャプチャ情報を出力しない）
	//ネットワークバイトオーダー変換を忘れずに。
	if( ntohs(frame->upper_protocol_type) != INTERNET_PROTOCOL_VERSION_4 )
		return;

	/************************************/
	/*           ファイル出力処理        */
	/************************************/

	//キャプチャ時刻
	fprintf(fp, "%d/%d/%d %d:%d:%d ",
		localtime->tm_year+1900, localtime->tm_mon+1, localtime->tm_mday,
		localtime->tm_hour, localtime->tm_min, localtime->tm_sec );

	//送信先IPv4アドレス     構造体定義のメンバ変数を利用し、明示的にアドレス情報を指定して出力します。
	fprintf(fp, "[ dst_ip = %d.%d.%d.%d   ",
		packet->dst_ip_addr.octet1, packet->dst_ip_addr.octet2,
		packet->dst_ip_addr.octet3, packet->dst_ip_addr.octet4 );

	//送信先MACアドレス
	fprintf(fp, "dst_mac = %x:%x:%x:%x:%x:%x ]   ",
		frame->dst_mac_addr.octet1, frame->dst_mac_addr.octet2, frame->dst_mac_addr.octet3,
		frame->dst_mac_addr.octet4, frame->dst_mac_addr.octet5, frame->dst_mac_addr.octet6 );

	//送信元IPv4アドレス
	fprintf(fp, "[ src_ip = %d.%d.%d.%d   ",
		packet->src_ip_addr.octet1, packet->src_ip_addr.octet2,
		packet->src_ip_addr.octet3, packet->src_ip_addr.octet4 );

	//送信元MACアドレス
	fprintf(fp, "[ src_mac = %x:%x:%x:%x:%x:%x ]\n",
		frame->src_mac_addr.octet1, frame->src_mac_addr.octet2, frame->src_mac_addr.octet3,
		frame->src_mac_addr.octet4, frame->src_mac_addr.octet5, frame->src_mac_addr.octet6 );
}
