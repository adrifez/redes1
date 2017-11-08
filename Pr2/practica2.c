/***************************************************************************
 practica2.c
 Muestra las direciones Ethernet de la traza que se pasa como primer parametro.
 Debe complatarse con mas campos de niveles 2, 3, y 4 tal como se pida en el enunciado.
 Debe tener capacidad de dejar de analizar paquetes de acuerdo a un filtro.

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez, Rafael Leira
 2017 EPS-UAM
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>

/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4			/* Tamanio de la direccion IP					*/
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define TRACE_END -2
#define NO_FILTER 0
#define TCP 6
#define UDP 17
void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack);

void handleSignal(int nsignal);

pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER};
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER};
uint16_t sport_filter= NO_FILTER;
uint16_t dport_filter = NO_FILTER;

void handleSignal(int nsignal)
{
	(void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

	printf("Control C pulsado (%"PRIu64" paquetes leidos)\n", contador);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv)
{
	uint8_t *pack = NULL;
	struct pcap_pkthdr *hdr;

	char errbuf[PCAP_ERRBUF_SIZE];
	char entrada[256];
	int long_index = 0, retorno = 0;
	char opt;

	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	if (argc > 1 && argc < 7) {
		if (strlen(argv[1]) < 256) {
			strcpy(entrada, argv[1]);
		}

	} else {
		printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{"i",required_argument, 0,'i'},
		{"ipo", required_argument, 0, '1'},
		{"ipd", required_argument, 0, '2'},
		{"po", required_argument, 0, '3'},
		{"pd", required_argument, 0, '4'},
		{"h", no_argument, 0, '5'},
		{0, 0, 0, 0}
	};

	//Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
	while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {
		switch (opt) {
		case 'i' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}
			
			if ( (descr = pcap_open_live(optarg, BUFSIZ, 0, 100, errbuf)) == NULL){
				printf("Error: pcap_open_live(): Interface: %s, %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
				exit(ERROR);
			}
			break;

		case 'f' :
			if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
				printf("Ha seleccionado más de una fuente de datos\n");
				pcap_close(descr);
				exit(ERROR);
			}

			if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
				printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
				exit(ERROR);
			}

			break;

		case '1' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipsrc_filter[0]), &(ipsrc_filter[1]), &(ipsrc_filter[2]), &(ipsrc_filter[3])) != IP_ALEN) {
				printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '2' :
			if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipdst_filter[0]), &(ipdst_filter[1]), &(ipdst_filter[2]), &(ipdst_filter[3])) != IP_ALEN) {
				printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '3' :
			if ((sport_filter= atoi(optarg)) == 0) {
				printf("Error po_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '4' :
			if ((dport_filter = atoi(optarg)) == 0) {
				printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
			}

			break;

		case '5' :
			printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;

		case '?' :
		default:
			printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
			exit(ERROR);
			break;
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	//Simple comprobacion de la correcion de la lectura de parametros
	printf("Filtro:");
	if(ipsrc_filter[0]!=0) printf("ipsrc_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
	if(ipdst_filter[0]!=0) printf("ipdst_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);

	if (sport_filter!= NO_FILTER) {
		printf("po_filtro=%"PRIu16"\t", sport_filter);
	}

	if (dport_filter != NO_FILTER) {
		printf("pd_filtro=%"PRIu16"\t", dport_filter);
	}

	printf("\n\n");

	do {
		retorno = pcap_next_ex(descr, &hdr, (const u_char **)&pack);

		if (retorno == PACK_READ) { //Todo correcto
			contador++;
			analizar_paquete(hdr, pack);
		
		} else if (retorno == PACK_ERR) { //En caso de error
			printf("Error al capturar un paquetes %s, %s %d.\n", pcap_geterr(descr), __FILE__, __LINE__);
			pcap_close(descr);
			exit(ERROR);

		}
	} while (retorno != TRACE_END);

	printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
	pcap_close(descr);
	
	return OK;
}



void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack)
{
	const uint8_t ip_t1 = 0x08, ip_t2 = 0x00;
	uint8_t aux = 0x00;
	uint16_t aux_s = 0x0000;
	int i = 0;
	int flag = 0;
	
	if(!hdr || !pack) return;

	printf("Nuevo paquete capturado el %s\n", ctime((const time_t *) & (hdr->ts.tv_sec)));
	
	//Campos eth
	
	printf("Direccion ETH destino= ");
	printf("%02X", pack[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf(":%02X", pack[i]);
	}

	printf("\n");
	pack += ETH_ALEN;

	printf("Direccion ETH origen = ");
	printf("%02X", pack[0]);

	for (i = 1; i < ETH_ALEN; i++) {
		printf(":%02X", pack[i]);
	}

	printf("\n");

	pack+=ETH_ALEN;
	
	//Ahora imprimimos el tipo de Ethernet
	printf("Tipo de ETH= ");
	printf("%02X%02X", pack[0], pack[1]);
	if(pack[0] != ip_t1 || pack[1] != ip_t2){ //Si no es de tipo IPv4 paramos de analizar el paquete
		printf("El siguiente protocolo no es de tipo IPv4\n\n");
		return;
	}
	
	pack+=ETH_TLEN;
	printf("\n");

	//Campos IP
	printf("Version: ");
	aux = pack[0]>>4;
	printf("%d\n", aux);
	aux = 0x00;
	aux = aux^(pack[0]<<4);
	printf("Longitud de cabecera: ");
	aux = aux>>4;
	printf("%d\n", aux);
	
	pack+=2;
	
	printf("Longitud total: ");
	memcpy(&aux_s, pack, sizeof(uint16_t));
	aux_s = ntohs(aux_s);
	printf("%d\n", aux_s);
	
	pack+=4;
	memcpy(&aux_s, pack, sizeof(uint16_t));
	aux_s = ntohs(aux_s);
	aux_s = aux_s<<3;
	printf("Posicion: ");
	aux_s = (aux_s>>3);
	printf("%d\n", aux_s);
	if (aux_s != 0x0000) {
		flag = 1;
	}
	
	pack+=2;
	printf("Tiempo de vida: ");
	printf("%d\n", pack[0]);
	
	printf("Protocolo: ");
	aux = pack[1];
	if(aux != TCP && aux != UDP){ //Si no es de tipo TCP o UDP paramos de analizar el paquete
		flag = 2;
	}
	printf("%d\n", pack[1]);
	
	pack+=4;
	printf("IP origen: ");
	printf("%d.%d.%d.%d\n", pack[0], pack[1], pack[2], pack[3]);
	if(ipsrc_filter[0] != NO_FILTER && ipsrc_filter[1] != NO_FILTER && ipsrc_filter[2] != NO_FILTER && ipsrc_filter[3] != NO_FILTER){
		if(ipsrc_filter[0] != pack[0] || ipsrc_filter[1] != pack[1] || ipsrc_filter[2] != pack[2] || ipsrc_filter[3] != pack[3]){
			printf("Este paquete no cumple el criterio de filtrado en IP origen\n\n");
			return;
		}
	}
	
	pack+=IP_ALEN;
	printf("IP destino: ");
	printf("%d.%d.%d.%d\n", pack[0], pack[1], pack[2], pack[3]);
	if(ipdst_filter[0] != NO_FILTER && ipdst_filter[1] != NO_FILTER && ipdst_filter[2] != NO_FILTER && ipdst_filter[3] != NO_FILTER){
		if(ipdst_filter[0] != pack[0] || ipdst_filter[1] != pack[1] || ipdst_filter[2] != pack[2] || ipdst_filter[3] != pack[3]){
			printf("Este paquete no cumple el criterio de filtrado en IP destino\n\n");
			return;
		}
	}
	
	if (flag == 1) { //No continuamos si no es el primer fragmento o si el siguiente protocolo no es TCP o UDP
		printf("El paquete IP leído no es el primer fragmento, de forma que no contendrá la cabecera de nivel 4.");
		
		return;
	} else if(flag == 2){
		printf("El siguiente protocolo no es de tipo TCP ni UDP\n\n");
		
		return;
	}

	pack+=IP_ALEN;
	printf("Puerto origen: ");
	memcpy(&aux_s, pack, sizeof(uint16_t));
	aux_s = ntohs(aux_s);
	printf("%d\n", aux_s);
	if(sport_filter != NO_FILTER){
		if(sport_filter != aux_s){
			printf("El paquete no cumple el filtro de puerto de origen\n\n");
			return;
		}
	}
	
	pack += 2;
	printf("Puerto destino: ");
	memcpy(&aux_s, pack, sizeof(uint16_t));
	aux_s = ntohs(aux_s);
	printf("%d\n", aux_s);
	if(dport_filter != NO_FILTER){
		if(dport_filter != aux_s){
			printf("El paquete no cumple el filtro de puerto de destino\n\n");
			return;
		}
	}
	pack += 2;

	switch(aux) {
		case TCP:
			pack += 9;
			aux = pack[0]<<3;
			aux = aux>>7;
			printf ("Flag ACK: %d\n", aux);
			aux = pack[0]<<6;
			aux = aux>>7;
			printf ("Flag SYN: %d\n", aux);
			break;

		case UDP:
			printf("Longitud: ");
			memcpy(&aux_s, pack, sizeof(uint16_t));
			aux_s = ntohs(aux_s);
			printf("%d\n", aux_s);
			break;

		default:
			printf("Protocolo de transporte desconocido.\n");
			break;
	}

	printf("\n\n");
}


