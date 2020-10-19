README k projektu IPK xsevci64
obsah xsevci64.tar
->README.txt
->manual.pdf
->main.c
->MakeFile

main.c program ktorý slúži na sniffovanie tcp alebo udp packetov
Spustenie:
1. make
2. ./ipk-sniffer -i rozhraní [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]
Príklad spustenia:
./ipk-sniffer -i eth0 -p 22
Výstup:
čas IP|FQDN : port > IP|FQDN : port

počet_vypsaných_bajtů:  výpis_bajtů_hexa výpis_bajtů_ASCII
Príklad:
11:52:49.079012 pcvesely.fit.vutbr.cz : 4093 > 10.10.10.56 : 80

0x0000:  00 19 d1 f7 be e5 00 04  96 1d 34 20 08 00 45 00  ........ ..4 ..
0x0010:  05 a0 52 5b 40 00 36 06  5b db d9 43 16 8c 93 e5  ..R[@.6. [..C....
0x0020:  0d 6d 00 50 0d fb 3d cd  0a ed 41 d1 a4 ff 50 18  .m.P..=. ..A...P.
0x0030:  19 20 c7 cd 00 00 99 17  f1 60 7a bc 1f 97 2e b7  . ...... .`z.....
0x0040:  a1 18 f4 0b 5a ff 5f ac 07 71 a8 ac 54 67 3b 39  ....Z._. .q..Tg;9
0x0050:  4e 31 c5 5c 5f b5 37 ed  bd 66 ee ea b1 2b 0c 26  N1.\_.7. .f...+.&
0x0060:  98 9d b8 c8 00 80 0c 57  61 87 b0 cd 08 80 00 a1  .......W a.......
