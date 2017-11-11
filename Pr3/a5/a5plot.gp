#!/usr/bin/gnuplot
#chmod +x a5plot.gp

# Para salida a un archivo tipo portable network graphics
set term pngcairo transparent enhanced font "arial,10" fontscale 1.0 size 600, 400

#Parametros
set xlabel "Delta"
set ylabel "P(d <= Delta)"
set key top left

#Plot
set title "ECDF delta IP 36.173.217.43 origen (TCP)"
set output "ECDF_delta_tcp_src.png"
plot "gnu.dat" using 1:2 with lines title "F(d)" lt rgb "red"

set output