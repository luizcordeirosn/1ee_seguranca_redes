import logging

logging.getLogger("scapy.run").setLevel(logging.ERROR)

from scapy.all import *
from scapy.layers.inet import IP, TCP

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
        packet = packet_ip / TCP(dport=x, flags='S')
        response = sr1(packet, timeout=0.5, verbose=0)
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print('Porta ' + str(x) + ' está aberta!!!\n')
        else:
            portClosed.append(x)
        sr1(packet_ip / TCP(dport=response.sport, flags='R'), timeout=0.5, verbose=0)
    except:
        portDenied.append(x)

print("Scan completo!!!\n")

print("Portas apenas fechadas: ")
print(portClosed)

print("\n")

print("Portas com acesso negado: ")
print(portDenied)


