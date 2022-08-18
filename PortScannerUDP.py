import logging

logging.getLogger("scapy.run").setLevel(logging.ERROR)

from scapy.all import *
from scapy.layers.inet import IP, UDP

#Verificar se a entrada foi digitada corretamente
if len(sys.argv) != 4:
    print("Erro durante escrita")
    print(f"Use: {sys.argv[0]} target startport endport")
    sys.exit(0)

target = str(sys.argv[1])
startPort = int(sys.argv[2])
endPort = int(sys.argv[3])

#Verificar se a startport é igual a endport
if startPort==endPort:
    endPort+=1

print(f"Scaneando {target} para abrir as portas TCP a partir da porta {startPort} até a porta {endPort} \n")

portClosed = []
portDenied = []

packet_ip = IP(dst=target)

for x in range(startPort, endPort+1):
    try:
        packet_udp = UDP(sport=x, dport=x)
        packet = packet_ip / packet_udp
        response = sr1(packet, timeout=2, verbose=0)
        print(f"Resposta: {packet.summary()} / Porta: {x}")
        if response.haslayer(UDP) and response.getlayer(UDP).flags == 0x12:
            print(f"Porta {x} está aberta")
        else:
            portClosed.append(x)
        sr1(packet_ip / packet_udp, timeout=2, verbose=0)
    except:
        portDenied.append(x)

print("\n")
print("Scan completo!!!\n")

print("Portas apenas fechadas: ")
print(portClosed)

print("\n")

print("Portas com acesso negado: ")
print(portDenied)


