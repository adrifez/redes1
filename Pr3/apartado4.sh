#!/bin/bash

tshark -r traza.pcap -qz io,stat,1,"SUM(frame.len)frame.len&&eth.src eq 00:11:88:CC:33:32","SUM(frame.len)frame.len&&eth.dst eq 00:11:88:CC:33:32" > a4/bw.dat