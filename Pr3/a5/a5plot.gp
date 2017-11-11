#!/usr/bin/gnuplot
#chmod +x a5plot.gp

# Para salida a un archivo tipo portable network graphics
set term pngcairo transparent enhanced font "arial,10" fontscale 1.0 size 600, 400

#Parametros
set xlabel "Delta"
set ylabel "P(d <= Delta)"
set key top left

#Plot
set title "ECDF delta direccion IP 36.173.217.43 origen (TCP)"
set output "ECDF_delta_tcp_src.png"
plot "plotTS.dat" using 1:2 with lines title "F(d)" lt rgb "red"

set title "ECDF delta direccion IP 36.173.217.43 destino (TCP)"
set output "ECDF_delta_tcp_dst.png"
plot "plotTD.dat" using 1:2 with lines title "F(d)" lt rgb "red"

#No existen datos para esta grafica
#set title "ECDF delta puerto UDP 49714 origen 49714"
#set output "ECDF_delta_udp_src.png"
#plot "plotUS.dat" using 1:2 with lines title "F(d)" lt rgb "red"

set title "ECDF delta puerto UDP 49714 destino 49714"
set output "ECDF_delta_udp_dst.png"
plot "plotUD.dat" using 1:2 with lines title "F(d)" lt rgb "red"


set output