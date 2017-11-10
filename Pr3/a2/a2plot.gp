#!/usr/bin/gnuplot
#chmod +x ipsrc.gp

# Parametros
set boxwidth 0.9 absolute
set style fill solid 1.00 border lt -1
set style histogram clustered gap 1 title textcolor lt -1
set datafile missing '-'
set style data histograms
set xtics border in scale 0,0 nomirror rotate by -45  autojustify

# Para salida a un archivo tipo portable network graphics
set terminal pngcairo transparent enhanced font "arial,10" fontscale 1.0 size 600, 400

# Plot

set xlabel "IP"

set ylabel "Bytes"
set title "Bytes por direccion IP"
set output "ip_src_bytes.png"
plot "ipsrcbytes.dat" using 2:xtic(1) ti "Bytes" lt rgb "red"
set output "ip_dst_bytes.png"
plot "ipdstbytes.dat" using 2:xtic(1) ti "Bytes" lt rgb "red"

set ylabel "Paquetes"
set title "Paquetes por direccion IP"
set output "ip_src_paquetes.png"
plot "ipsrcpaquetes.dat" using 2:xtic(1) ti "Paquetes" lt rgb "blue"
set output "ip_dst_paquetes.png"
plot "ipdstpaquetes.dat" using 2:xtic(1) ti "Paquetes" lt rgb "blue"


set xlabel "Puerto TCP"

set ylabel "Bytes"
set title "Bytes por puerto TCP"
set output "tcp_src_bytes.png"
plot "tcpsrcbytes.dat" using 2:xtic(1) ti "Bytes" lt rgb "red"
set output "tcp_dst_bytes.png"
plot "tcpdstbytes.dat" using 2:xtic(1) ti "Bytes" lt rgb "red"

set ylabel "Paquetes"
set title "Paquetes por puerto TCP"
set output "tcp_src_paquetes.png"
plot "tcpsrcpaquetes.dat" using 2:xtic(1) ti "Paquetes" lt rgb "blue"
set output "tcp_dst_paquetes.png"
plot "tcpdstpaquetes.dat" using 2:xtic(1) ti "Paquetes" lt rgb "blue"


set xlabel "Puerto UDP"

set ylabel "Bytes"
set title "Bytes por puerto UDP"
set output "udp_src_bytes.png"
plot "udpsrcbytes.dat" using 2:xtic(1) ti "Bytes" lt rgb "red"
set output "udp_dst_bytes.png"
plot "udpdstbytes.dat" using 2:xtic(1) ti "Bytes" lt rgb "red"

set ylabel "Paquetes"
set title "Paquetes por puerto UDP"
set output "udp_src_paquetes.png"
plot "udpsrcpaquetes.dat" using 2:xtic(1) ti "Paquetes" lt rgb "blue"
set output "udp_dst_paquetes.png"
plot "udpdstpaquetes.dat" using 2:xtic(1) ti "Paquetes" lt rgb "blue"

# Cierra el archivo de salida
set output