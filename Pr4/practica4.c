/***************************************************************************
 practica4.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones
 
 Compila: make
 Autor: Jose Luis Garcia Dorado
 2014 EPS-UAM v2
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "interface.h"
#include "practica4.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char interface[10];	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP


void handleSignal(int nsignal){
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){	

	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];


	int long_index=0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0;


	FILE *archivo_datos=NULL;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"h",no_argument,0,'5'},
		{0,0,0,0}
	};

		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
					//Por comodidad definimos interface como una variable global
				sprintf(interface,"%s",optarg);
				break;

			case '2' : 

				flag_ip = 1;
					//Leemos la IP a donde transmitir y la almacenamos en orden de red
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
					//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
				puerto_destino=atoi(optarg);
				break;

			case '4' :

				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof(data), stdin)==NULL) {
						printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					archivo_datos=fopen(optarg, "r");
					if(archivo_datos==NULL) {
						printf("Error al abrir el archivo %s.\n",optarg);
						return ERROR;
					}
					if (fgets(data, sizeof(data), archivo_datos)==NULL) {
						printf("Error leyendo desde el archivo de datos: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					fclose(archivo_datos);
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
				}
				flag_file = 1;

				break;

			case '5' : printf("Ayuda. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' : printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;

			default: printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip IP -pd Puerto <-f /ruta/fichero_a_transmitir o stdin>: %d\n",argv[0],argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n",interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",IP_destino_red[0],IP_destino_red[1],IP_destino_red[2],IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n",puerto_destino);
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); //Deben ser pares!
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
		//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
		//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
		//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet

		//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);

		//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
		//Primero un paquete UDP
		//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;
		//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp; memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); parametros_udp.puerto_destino=puerto_destino;
		//Enviamos
	if(enviar((uint8_t*)data,strlen(data),pila_protocolos,&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);

		//Luego, un paquete ICMP en concreto un ping
	pila_protocolos[0]=ICMP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=0;
	Parametros parametros_icmp; parametros_icmp.tipo=PING_TIPO; parametros_icmp.codigo=PING_CODE; memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	if(enviar((uint8_t*)"Probando a hacer un ping", strlen("Probando a hacer un ping"), pila_protocolos, &parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);

		//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
* Nombre: enviar 									*
* Descripcion: Esta funcion envia un mensaje						*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio (struct parametros)			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t enviar(uint8_t* mensaje, uint64_t longitud,uint16_t* pila_protocolos,void *parametros){
	uint16_t protocolo=pila_protocolos[0];
printf("Enviar(%"PRIu16") %s %d.\n",protocolo,__FILE__,__LINE__);
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	}
	else {
		return protocolos_registrados[protocolo](mensaje,longitud,pila_protocolos,parametros);
	}
	return ERROR;
}

/****************************************************************************************
* Nombre: moduloUDP 									*
* Descripcion: Esta funcion implementa el modulo de envio UDP				*
* Argumentos: 										*
*  -mensaje: mensaje a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/
uint8_t moduloUDP(uint8_t* mensaje,uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint8_t segmento[UDP_SEG_MAX]={0};
	uint8_t *aux=NULL;
	int i=0;
	uint16_t puerto_origen = 0,suma_control=0;
	uint16_t aux16;
	uint64_t pos=0;
	uint16_t protocolo_inferior=pila_protocolos[1];
	
	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud>(pow(2,16)-UDP_HLEN)){
		printf("Error: mensaje demasiado grande para UDP (%f).\n",(pow(2,16)-UDP_HLEN));
		return ERROR;
	}

	Parametros udpdatos=*((Parametros*)parametros);
	uint16_t puerto_destino=udpdatos.puerto_destino;
	if(obtenerPuertoOrigen(&puerto_origen)==ERROR) return ERROR;
	aux16=htons(puerto_origen);

	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	memcpy(segmento+pos,&puerto_destino,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	memcpy(segmento+pos,&longitud,sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	//El checksum se deja a 0 por simplicidad
	aux16=0x0000;
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
	//memcpy(segmento+pos,mensaje,longitud); //Tenemos que comprobar que el orden es el correcto
	aux=segmento+pos;
	for(i=0; i < longitud; i++){
		aux[i]=mensaje[i];
	}
	pos+=longitud;

	//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,pos,pila_protocolos,parametros);
}


/****************************************************************************************
* Nombre: moduloIP 									*
* Descripcion: Esta funcion implementa el modulo de envio IP				*
* Argumentos: 										*
*  -segmento: segmento a enviar								*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el segmento						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
*
* ***************************************************************************************/
uint8_t moduloIP(uint8_t* segmento, uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	srand(NULL);
	int fragmentos=-1, i, j, last_size;
	uint64_t length=0, aux64;
	uint8_t datagrama[IP_DATAGRAM_MAX]={0}, flag_subred=0;
	uint32_t aux32;
	uint16_t aux16, aux16_1=0x0000, random_id, mtu, fl_off, offset;
	uint8_t aux8, *aux=NULL, aux8_cs[2]={0};
	uint32_t pos=0,pos_control=0;
	uint8_t IP_origen[IP_ALEN], default_gateway[IP_ALEN];
	uint16_t protocolo_superior=pila_protocolos[0];
	uint16_t protocolo_inferior=pila_protocolos[2];
	pila_protocolos++;
	uint8_t mascara[IP_ALEN],IP_rango_origen[IP_ALEN],IP_rango_destino[IP_ALEN];

	printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino=ipdatos.IP_destino;
	
	if(obtenerIPInterface(interface, IP_origen) == ERROR) return ERROR;
	
	if(obtenerMascaraInterface(interface, mascara) == ERROR) return ERROR;
	
	//Comprobamos si la ip de origen y la de destino estan en la misma subred
	if(aplicarMascara(IP_origen, mascara, IP_ALEN, IP_rango_origen) == ERROR) return ERROR;
	if(aplicarMascara(ipdatos.IP_destino, mascara, IP_ALEN, IP_rango_destino) == ERROR) return ERROR;
	
	for(i=0; i<IP_ALEN; i++){ //Comprobamos si estan en la misma subred
		if(IP_rango_origen[i] != IP_rango_destino[i]){ //Si no son iguales
			flag_subred=-1;
		}
	}
	
	if(flag_subred == 0){ //Si estan en la misma subred
		if(ARPrequest(interface, IP_destino, (Parametros*)parametros.ETH_destino) == ERROR) return ERROR; //Obtenemos la MAC a la que hemos de enviar el paquete
	} else{ //Si no estan en la misma subred
		if(obtenerGateway(interface, default_gateway)==ERROR) return ERROR; //IP del siguiente salto
		if(ARPrequest(interface, default_gateway, (Parametros*)parametros.ETH_destino) == ERROR) return ERROR; //Obtenemos la MAC a la que hemos de enviar el paquete
	}
	
	datagrama[0]=0x45; // IPv4 IHL=5 -> 5 palabras de 32 bits
	datagrama[1]=(Parametros*)parametros.tipo; //Tipo

	random_id = (uint16_t) rand() % MAX_PROTOCOL; //Generamos un numero de 16 bits aleatorio
	random_id=htons(random_id);
	memcpy(datagrama+4, &random_id, sizeof(random_id));

	aux64 = longitud + (5*4); //5 palabras de 32 bits = 5 palabras de 4 bytes
	if(aux64 > IP_DATAGRAM_MAX){
		perror("El paquete excede el tamanio maximo para un datagrama");
		
		return ERROR;
	}
	
	if(obtenerMTUInterface(interface, &mtu)==ERROR) return ERROR;
	if(aux64 > (uint64_t)mtu){ //En este caso fragmentamos, veamos el numero de fragmentos
		fragmentos = (int)ceil((double)(aux64-5*4)/(double)(mtu-5*4)); //Restamos el tamanio destinado a la cabecera IP
		last_size = (aux64-5*4) - ((fragmentos-1)*(mtu-5*4)); //Tamanio del ultimo fragmento de datos
	}
	
	aux=datagrama+6;
	aux[0]=0x00; //Flags y primer bit de posicion por defecto
	aux[1]=0x00; //Resto de posicion por defecto
	aux[2]=128;  //Tiempo de vida por defecto
	//Nota: si se fragmenta se cambian despues los campos necesarios

	//UDP->17, ICMP->1
	aux+=2;
	if(protocolo_superior == UDP_PROTO){
		aux[1] = 17;
	} else if(protocolo_superior == ICMP_PROTO){
		aux[1] = 1;
	} else return ERROR;
	
	//Suma de control de cabecera
	aux+=2;
	aux[0]=0x00;
	aux[1]=0x00:
	
	aux+=4;
	aux[0]=IP_origen[0];
	aux[1]=IP_origen[1];
	aux[2]=IP_origen[2];
	aux[3]=IP_origen[3];

	aux+=4;
	aux[0]=IP_destino[0];
	aux[1]=IP_destino[1];
	aux[2]=IP_destino[2];
	aux[3]=IP_destino[3];
	
	aux+=4; //aux=datagrama+(4*5)
	
	if(fragmentos == -1){ //Si no hay fragmentacion, enviamos el paquete
		aux16=(uint16_t)aux64;
		aux16=htons(aux16);
		memcpy(datagrama+2, &aux16, sizeof(aux16)); //Longitud total
		
		if(calcularChecksum(5*4, datagrama, aux8_cs)==ERROR) return ERROR;
		//memcpy(aux, segmento, longitud); //Despues de la cabecera IP, viene la UDP con los datos; Tenemos que comprobar el orden
		//Copiamos la cabecera UDP y los datos
		for(i=0; i<longitud; i++){
			aux[i]=segmento[i];
		}
		
		//Fijamos el checksum
		aux=datagrama+(10);
		aux[0]=aux8_cs[0];
		aux[1]=aux8_cs[1];
		
		return protocolos_registrados[protocolo_inferior](datagrama,aux64,pila_protocolos,parametros);
	}
	
	for(i=0; i<fragmentos; i++){ //Fragmentamos el paquete
		if(i != (fragmentos-1)){
			aux=datagrama+(6);
			aux16 = 0x2000; //Los 3 bits de flags son 001 divisible(2º cero) more fragments (3er 1)
			if(i!=0)aux16_1+=mtu-(5*4); //Offset (posicion)=tamanio maximo-tamanio de la cabecera (ya que es el offset del segmento)
			offset=aux16_1/8; //Se mide en el orden de 64 Bytes
			fl_off=aux16|offset;
			fl_off=htons(fl_off);			
			memcpy(aux, &fl_off, sizeof(fl_off));
			
			aux=datagrama+(4*5);
			for(j=0; j<(mtu-(5*4)); j++){ //Fijamos su correspondiente fragmento
				aux[j]=segmento[j+aux16_1]; //sumamos el offset
			}
			
			aux16=(uint16_t)mtu;
			aux16=htons(aux16);
			memcpy(datagrama+2, &aux16, sizeof(aux16)); //Longitud total
		
			if(calcularChecksum(5*4, datagrama, aux8_cs)==ERROR) return ERROR;
		
			//Fijamos el checksum
			aux=datagrama+(10);
			aux[0]=aux8_cs[0];
			aux[1]=aux8_cs[1];
			
			protocolos_registrados[protocolo_inferior](datagrama,mtu,pila_protocolos,parametros);		
		}
		if(i == (fragmentos-1)){ //El ultimo fragmento
			//No hay mas fragmentos
			aux=datagrama+(6);
			aux16_1+=mtu-(5*4);
			offset=aux16_1/8;
			memcpy(aux, &offset, sizeof(offset));
			
			aux=datagrama+(4*5);
			for(j=0; j<last_size; j++){ //Fijamos su correspondiente fragmento
				aux[j]=segmento[j+aux16_1];
			}
			for(j=last_size; j < mtu-(5*4); j++){ //Vaciamos el resto del datagrama (aunque no es necesario)
				aux[j]=0;
			}
			
			aux16=(uint16_t)last_size+5*4;
			aux16=htons(aux16);
			memcpy(datagrama+2, &aux16, sizeof(aux16)); //Longitud total
		
			if(calcularChecksum(5*4, datagrama, aux8_cs)==ERROR) return ERROR;
		
			//Fijamos el checksum
			aux=datagrama+(10);
			aux[0]=aux8_cs[0];
			aux[1]=aux8_cs[1];
			
			return protocolos_registrados[protocolo_inferior](datagrama,(uint64_t)last_size+5*4,pila_protocolos,parametros);	
		}
	}
}


/****************************************************************************************
* Nombre: moduloETH 									*
* Descripcion: Esta funcion implementa el modulo de envio Ethernet			*
* Argumentos: 										*
*  -datagrama: datagrama a enviar							*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el datagrama						*
*  -parametros: Parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloETH(uint8_t* datagrama, uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
	int i;
	uint8_t trama[ETH_FRAME_MAX]={0}, *aux=NULL;
	uint8_t ETH_destino[ETH_ALEN], ETH_origen[ETH_ALEN];
	uint16_t protocolo_superior=pila_protocolos[1];
	uint16_t eth_t;
	struct pcap_pkthdr *cabecera=NULL;

	printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);	

	if(longitud+ETH_HLEN > ETH_FRAME_MAX){
		perror("El paquete excede el tamanio maximo");
		
		return ERROR;
	}
	
	ETH_destino = ((Parametros*)parametros)->ETH_destino;
	if(obtenerMACdeInterface(interface, ETH_origen) == ERROR) return ERROR;
	
	aux=trama;
	aux[0]=ETH_destino[0];
	aux[1]=ETH_destino[1];
	aux[2]=ETH_destino[2];
	aux[3]=ETH_destino[3];
	aux[4]=ETH_destino[4];
	aux[5]=ETH_destino[5];
	
	aux+=6;
	aux[0]=ETH_origen[0];
	aux[1]=ETH_origen[1];
	aux[2]=ETH_origen[2];
	aux[3]=ETH_origen[3];
	aux[4]=ETH_origen[4];
	aux[5]=ETH_origen[5];
	
	aux+=6;
	eth_t = htons(protocolo_superior);
	memcpy(aux, &eth_t, sizeof(eth_t));
	
	aux+=2;
	for(i=0; i<longitud; i++){
		aux[i]=datagrama[i];
	}
	
	if(pcap_sendpacket(descr, trama, longitud+ETH_HLEN) != 0) return ERROR;
	
	pcap_dump(pdumper, cabecera, trama);

//TODO
//Almacenamos la salida por cuestiones de debugging [...]
	
	return OK;
}


/****************************************************************************************
* Nombre: moduloICMP 									*
* Descripcion: Esta funcion implementa el modulo de envio ICMP				*
* Argumentos: 										*
*  -mensaje: mensaje a anadir a la cabecera ICMP					*
*  -pila_protocolos: conjunto de protocolos a seguir					*
*  -longitud: bytes que componen el mensaje						*
*  -parametros: parametros necesario para el envio este protocolo			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t moduloICMP(uint8_t* mensaje,uint64_t longitud, uint16_t* pila_protocolos,void *parametros){
//TODO
//[....]

}


/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
* Nombre: aplicarMascara 								*
* Descripcion: Esta funcion aplica una mascara a un vector				*
* Argumentos: 										*
*  -IP: IP a la que aplicar la mascara en orden de red					*
*  -mascara: mascara a aplicar en orden de red						*
*  -longitud: bytes que componen la direccion (IPv4 == 4)				*
*  -resultado: Resultados de aplicar mascara en IP en orden red				*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint32_t longitud, uint8_t* resultado){
	int i;

	if(!IP || !mascara || longitud < 0 || !resultado) return ERROR;
	
	for(i = 0; i < longitud; i++){
		resultado[i] = IP[i]&mascara[i]; //Aplicamos la mascara a nivel de bit	
	}
	
	return OK;
}


/***************************Funciones auxiliares implementadas**************************************/

/****************************************************************************************
* Nombre: mostrarPaquete 								*
* Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector		*
* Argumentos: 										*
*  -paquete: bytes que conforman un paquete						*
*  -longitud: Bytes que componen el mensaje						*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t mostrarPaquete(uint8_t * paquete, uint32_t longitud){
	uint32_t i;
	printf("Paquete:\n");
	for (i=0;i<longitud;i++){
		printf("%02"PRIx8" ", paquete[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
* Nombre: calcularChecksum							     	*
* Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP		*
* Argumentos:										*
*   -longitud: numero de bytes de los datos sobre los que calcular el checksum		*
*   -datos: datos sobre los que calcular el checksum					*
*   -checksum: checksum de los datos (2 bytes) en orden de red! 			*
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t calcularChecksum(uint16_t longitud, uint8_t *datos, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;       
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;      
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
* Nombre: inicializarPilaEnviar     							*
* Descripcion: inicializar la pila de red para enviar registrando los distintos modulos *
* Retorno: OK/ERROR									*
****************************************************************************************/

uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	
//TODO
//A registrar los modulos de UDP y ICMP [...] 

	return OK;
}


/****************************************************************************************
* Nombre: registrarProtocolo 								*
* Descripcion: Registra un protocolo en la tabla de protocolos 				*
* Argumentos:										*
*  -protocolo: Referencia del protocolo (ver RFC 1700)					*
*  -handleModule: Funcion a llamar con los datos a enviar				*
*  -protocolos_registrados: vector de funciones registradas 				*
* Retorno: OK/ERROR 									*
*****************************************************************************************/

uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){		
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}


