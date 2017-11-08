/***************************************************************************
 practica1.c
 Muestra el tiempo de llegada de los primeros 500 paquetes a la interface eth0
y los vuelca a traza (¿correctamente?) nueva con tiempo actual

 Compila: gcc -Wall -o EjemploPcapNextEx EjemploPcapNextEx.c -lpcap
 Autores: Adrián Fernández Amador y Santiago Glez- Carvajal Centenera
 2017 EPS-UAM
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#define OK 0
#define ERROR 1

#define ETH_FRAME_MAX 1514	// Tamanio maximo trama ethernet

pcap_t *descr=NULL,*descr2=NULL;
pcap_dumper_t *pdumper=NULL;

int contador;

void handle(int nsignal){
	printf("\nControl C pulsado\nPaquetes recibidos: %d\n", contador);
	if(descr)
		pcap_close(descr);
	if(descr2)
		pcap_close(descr2);
	if(pdumper)
		pcap_dump_close(pdumper);
	exit(OK);
 }

int main(int argc, char **argv)
{
	int i = 0;
	int retorno=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t *paquete=NULL;
	struct pcap_pkthdr *cabecera=NULL;
	char file_name[256];
	struct timeval time;
	int nBytes;
	char traza[50];
	int flag = 0;
	
	if(argc <= 1 || argc > 3){
		printf("Error: Numero de argumentos invalido\n\tEl programa ha de ser invocado de una de las siguientes maneras:\n\tpractica1 <numero_bytes_a_mostrar>\n\tpractica1 <numero_bytes_a_mostrar> <traza_a_analizar>\n");
		exit(ERROR);
	}
	nBytes = atoi(argv[1]);
	if(nBytes <= 0){
		printf("El primer argumento es invalido; ha de ser mayor que 0");
		exit(ERROR);
	}
	
	if (argc == 3) {
		strcpy(traza, argv[2]);
		flag = 1; /*Modo traza*/
	}

	if(signal(SIGINT,handle)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}	
	
	if (flag == 0) {
			/*Apertura de interface*/
		if ((descr = pcap_open_live("eth0",BUFSIZ,0,100, errbuf)) == NULL){/*Capturaos el paquete entero*/
			printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
			exit(ERROR);
		}
	} else {
			/*Apertura de traza*/
		if ((descr = pcap_open_offline(traza, errbuf)) == NULL){
			printf("Error: pcap_open_offline(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
			exit(ERROR);
		}
	}	
	
	if (flag == 0) {
			/*Volcado de traza*/
		descr2=pcap_open_dead(DLT_EN10MB,ETH_FRAME_MAX);
		if (!descr2){
			printf("Error al abrir el dump.\n");
			pcap_close(descr);
			exit(ERROR);
		}
		gettimeofday(&time,NULL);
		sprintf(file_name,"eth0.%lld.pcap",(long long)time.tv_sec);
		pdumper=pcap_dump_open(descr2,file_name);
		if(!pdumper){
			printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr2),__FILE__,__LINE__);
			pcap_close(descr);
			pcap_close(descr2);
		}
	}

	while (contador < 500 || flag){
		retorno = pcap_next_ex(descr,&cabecera,(const u_char **)&paquete);
		if(retorno == -1){ 		//En caso de error
			printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
			pcap_close(descr);
			if (flag == 0) {
				pcap_close(descr2);
				pcap_dump_close(pdumper);
			}
			exit(ERROR);
		}
		else if(retorno == 0){
			continue;
		}
		else if(retorno==-2){
			printf("Paquetes recibidos: %d\n", contador);
			break;
		}
			/*En otro caso*/
		contador++;
		cabecera->ts.tv_sec += (double) 2*24*60*60; /*+2 dias*/
				
		printf("Nuevo paquete capturado: ");
		i = 0;
		while(i < nBytes && i < cabecera->len){
			printf("%02x ", paquete[i]);
			i++;
		}
		printf("\n");
		if(pdumper && flag == 0){
			pcap_dump((uint8_t *)pdumper,cabecera,paquete);
		}
	}
	
	pcap_close(descr);
	if (flag == 0) {
		pcap_close(descr2);
		pcap_dump_close(pdumper);
	}
	return OK;
}

