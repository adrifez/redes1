#!/usr/bin/gnuplot
#chmod +x ipsrc.gp

# Salida por pantalla simple: sudo apt-get install gnuplot-x11; set term 11
set term dumb

# Parametros
set title "ip_src_bytes"
set xlabel "IP"
set ylabel "Bytes"

# Para salida a un archivo tipo portable network graphics
set term pngcairo
set output "ip_src_bytes.png"

# Plot
plot "ipsrcbytes.dat" using 1:2 with steps title "Bytes"

# Cierra el archivo de salida
set output
