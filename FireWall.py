from scapy.all import *

# Güvenlik duvarı kuralları için boş bir liste oluşturun
firewall_rules = []

# Ağ trafiğini yakalayın
def packet_callback(packet):
    # Yakalanan paketi analiz edin ve eğer kurala uygunsa gönderin, değilse engelleyin
    if check_firewall_rules(packet):
        send(packet)
    else:
        print("Paket engellendi: " + str(packet.summary()))

# Güvenlik duvarı kurallarını kontrol edin
def check_firewall_rules(packet):
    for rule in firewall_rules:
        if packet.haslayer(rule):
            return False
    return True

# Ana kod akışını başlatın
if __name__ == '__main__':
    # Güvenlik duvarı kurallarını yükleyin
    firewall_rules.append(TCP)
    firewall_rules.append(IP)

    # Ağ trafiğini dinleyin
    sniff(prn=packet_callback, filter="tcp")

