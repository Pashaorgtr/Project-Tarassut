#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Project Tarassut - pasha.org.tr Projesi
Geliştirici: Hasan Yasin Yaşar
Lisans: PSH 1.0

Bu script, ağ trafiğini pasif olarak dinleyerek internet (WAN) üzerindeki
IPv4 adresleri ile bu adreslerle ilişkili alan adlarını (domain) tespit eder.
Toplanan veriler, bir Pasif DNS (PDNS) haritası oluşturmak üzere periyodik
olarak pasha.org.tr API'sine gönderilir.

Bu araç, ağ trafiği analizi ve siber güvenlik araştırmaları için veri toplamayı amaçlar.
"""

import os
import sys
import json
import time
import signal
import logging
import threading
from dotenv import load_dotenv, set_key, dotenv_values
from datetime import datetime
from pathlib import Path
import socket
import struct
from typing import Optional, List, Dict, Set
from collections import defaultdict
import re

try:
    import requests
except ImportError:
    print("HATA: Gerekli 'requests' kütüphanesi bulunamadı.")
    print("Lütfen 'pip install requests' komutu ile kurun.")
    sys.exit(1)

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, DNS, DNSRR
    from scapy.layers.http import HTTPRequest
except ImportError:
    print("HATA: Gerekli 'scapy' kütüphanesi bulunamadı.")
    print("Lütfen 'pip install scapy' komutu ile kurun.")
    sys.exit(1)

# --- Yapılandırma ---
CONFIG = {
    "API_URL": "https://pasha.org.tr/api/tarassut",
    "SAVE_INTERVAL_SECONDS": 300,  # 5 dakika
    "LOG_LEVEL": logging.INFO,
    "HTTP_ANALYSIS_ENABLED": True,
    "PASSIVE_DNS_ENABLED": True,
}

# --- Loglama Kurulumu ---
logging.basicConfig(
    level=CONFIG["LOG_LEVEL"],
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def ensure_user_info():
    """
    Kullanıcı bilgilerinin (.env dosyasında) mevcut olduğunu kontrol eder.
    Eksik bilgi varsa, kullanıcıdan alınarak dosyaya yazılır.
    """
    dotenv_path = Path(".env")
    load_dotenv(dotenv_path)

    required_fields = {
        "USER_FULLNAME": "İsim Soyisim",
        "USER_USERNAME": "Kullanıcı Adı",
        "USER_EMAIL": "E-posta",
        "USER_LINKEDIN": "LinkedIn",
        "USER_GITHUB": "GitHub"
    }

    missing_fields = [key for key in required_fields if not os.getenv(key)]

    if missing_fields:
        print("Project Tarassut'a katkıda bulunmak için lütfen kullanıcı bilgilerinizi girin:")
        for key in missing_fields:
            value = input(f"{required_fields[key]}: ").strip()
            set_key(dotenv_path, key, value)
        print("✓ Bilgiler kaydedildi. Program başlatılıyor...")
    else:
        print("✓ Kullanıcı bilgileri bulundu.")


class WANHarvester:
    """
    Sadece internet (WAN) trafiğini analiz ederek IP adresleri ve alan adları
    arasında Pasif DNS (PDNS) haritalaması yapan sınıf.
    """

    def __init__(self):
        """Harvester sınıfını başlatır."""
        self.ip_to_domains = defaultdict(set)
        self.running = False
        self.packet_count = 0
        self.lock = threading.Lock()

    def _add_mapping(self, ip: str, domain: Optional[str] = None):
        """
        Bir genel (public) IP adresini ve (varsa) ilişkili alan adını bellekteki
        haritaya güvenli bir şekilde ekler.
        """
        if not self._is_valid_ipv4(ip) or self._is_private_ip(ip):
            return

        with self.lock:
            if domain:
                clean_domain = re.sub(r'^\*\.', '', domain).strip().lower()
                self.ip_to_domains[ip].add(clean_domain)
            else:
                if ip not in self.ip_to_domains:
                    self.ip_to_domains[ip] = set()

    def _is_private_ip(self, ip: str) -> bool:
        """Verilen IP adresinin özel (private) bir ağa ait olup olmadığını kontrol eder (RFC 1918)."""
        try:
            if ip.startswith("127."):
                return True
            ip_addr = struct.unpack('!I', socket.inet_aton(ip))[0]
            return (
                (ip_addr >= 167772160 and ip_addr <= 184549375) or
                (ip_addr >= 2886729728 and ip_addr <= 2887778303) or
                (ip_addr >= 3232235520 and ip_addr <= 3232301055)
            )
        except (socket.error, ValueError):
            return False

    def _is_valid_ipv4(self, ip: str) -> bool:
        """Verilen string'in geçerli bir IPv4 adresi formatında olup olmadığını kontrol eder."""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def _packet_handler(self, packet: scapy.packet.Packet):
        """
        Scapy tarafından yakalanan her bir paketi işleyen ana fonksiyondur.
        Paketleri ilgili analiz fonksiyonlarına yönlendirir.
        """
        self.packet_count += 1

        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if self._is_private_ip(src_ip) and self._is_private_ip(dst_ip):
            return

        self._analyze_ip_packet(packet)

        if CONFIG["PASSIVE_DNS_ENABLED"] and packet.haslayer(DNS):
            self._analyze_dns_packet(packet)

        if CONFIG["HTTP_ANALYSIS_ENABLED"] and packet.haslayer(HTTPRequest):
            self._analyze_http_packet(packet)

        # --- KALDIRILDI: Sürekli akan "İşlenen paket" logu kaldırıldı. ---

    def _analyze_ip_packet(self, packet: scapy.packet.Packet):
        """IP katmanından kaynak ve hedef IP adreslerini çıkarır."""
        self._add_mapping(packet[IP].src)
        self._add_mapping(packet[IP].dst)

    def _analyze_dns_packet(self, packet: scapy.packet.Packet):
        """DNS yanıt paketlerindeki (A kaydı) alan adı ve IP eşleşmelerini çıkarır."""
        if not packet.haslayer(DNSRR):
            return

        for i in range(packet[DNS].ancount):
            rr = packet[DNS].an[i]
            if rr.type == 1 and hasattr(rr, 'rdata'):
                domain = rr.rrname.decode('utf-8', errors='ignore').rstrip('.')
                ip = rr.rdata
                self._add_mapping(ip, domain)
                logging.debug(f"[PDNS EŞLEŞMESİ] DNS: {domain} -> {ip}")

    def _analyze_http_packet(self, packet: scapy.packet.Packet):
        """Şifrelenmemiş HTTP isteklerindeki 'Host' başlığından alan adı-IP eşleşmesini çıkarır."""
        try:
            host_bytes = packet[HTTPRequest].Host
            if host_bytes:
                domain = host_bytes.decode('utf-8', errors='ignore')
                ip = packet[IP].dst
                self._add_mapping(ip, domain)
                logging.debug(f"[PDNS EŞLEŞMESİ] HTTP: {domain} -> {ip}")
        except Exception as e:
            logging.debug(f"HTTP paket analizi sırasında hata: {e}")

    def send_data_to_api(self):
        """Toplanan IP-domain haritasını merkezi API'ye gönderir."""
        with self.lock:
            if not self.ip_to_domains:
                # --- DEĞİŞTİRİLDİ: Mesaj daha anlaşılır hale getirildi. ---
                logging.info("Periyodik kontrol: Gönderilecek yeni veri birikmedi.")
                return
            
            ip_mappings_list = [
                {"ip": ip, "domains": sorted(list(domains))}
                for ip, domains in self.ip_to_domains.items()
            ]

        # --- DEĞİŞTİRİLDİ: Daha detaylı bir özet mesajı oluşturuldu. ---
        total_ips = len(ip_mappings_list)
        total_domains = sum(len(mapping["domains"]) for mapping in ip_mappings_list)

        logging.info(
            f"VERİ GÖNDERİLİYOR -> {total_ips} benzersiz IP ve bu IP'lerle ilişkili {total_domains} domain eşleşmesi API'ye aktarılıyor..."
        )

        try:
            user_info = dotenv_values(".env")
            payload = {
                "user": {
                    "fullname": user_info.get("USER_FULLNAME", ""),
                    "username": user_info.get("USER_USERNAME", ""),
                    "email": user_info.get("USER_EMAIL", ""),
                    "linkedin": user_info.get("USER_LINKEDIN", ""),
                    "github": user_info.get("USER_GITHUB", "")
                },
                "source": "app.py (PDNS-Harvester)",
                "collected_at": datetime.now().isoformat(),
                "ip_mappings": ip_mappings_list
            }

            headers = {"Content-Type": "application/json"}
            response = requests.post(CONFIG["API_URL"], json=payload, headers=headers, timeout=30)

            if response.status_code == 201:
                logging.info(f"VERİ GÖNDERİLDİ -> Sunucu yanıtı başarılı.")
                with self.lock:
                    self.ip_to_domains.clear()
            else:
                logging.error(f"API'ye veri gönderilemedi. Durum Kodu: {response.status_code}, Yanıt: {response.text}")

        except requests.exceptions.RequestException as e:
            logging.error(f"API bağlantı hatası: {e}")
        except Exception as e:
            logging.error(f"Veri gönderme sırasında beklenmedik bir hata oluştu: {e}")

    def _auto_save_loop(self):
        """Belirlenen aralıklarla API'ye veri gönderimini tetikleyen döngü."""
        while self.running:
            time.sleep(CONFIG["SAVE_INTERVAL_SECONDS"])
            if self.running:
                self.send_data_to_api()

    def start_monitoring(self, interface: Optional[str] = None):
        """
        Ağ dinleme işlemini başlatır ve programın kesintisiz çalışmasını sağlar.
        Olası dinleme hatalarında kendini yeniden başlatır.
        """
        self.running = True
        
        threading.Thread(target=self._auto_save_loop, daemon=True).start()
        
        print("\n" + "=" * 70)
        print("     Project Tarassut - İnternet Trafik Haritalama Aracı")
        print("=" * 70)
        print(f"✓ Pasif DNS ve HTTP analizi ile ağ trafiği dinleniyor.")
        print(f"✓ Toplanan veriler her {CONFIG['SAVE_INTERVAL_SECONDS']} saniyede bir pasha.org.tr API'sine gönderilecek.")
        print("✓ Program arka planda sessizce çalışacaktır. Özetler konsola yazdırılacaktır.")
        print("✓ Çıkmak için CTRL+C tuşlarına basın.")
        logging.info(f"İzlenen arayüz: {interface or 'Tüm Arayüzler'}")
        print("=" * 70 + "\n")

        while self.running:
            try:
                scapy.sniff(
                    iface=interface,
                    prn=self._packet_handler,
                    store=False,
                    stop_filter=lambda p: not self.running
                )
            except (PermissionError, OSError):
                logging.critical("HATA: Ağ dinleme yetkisi yok. Lütfen programı 'sudo' ile çalıştırın.")
                self.running = False
            except Exception as e:
                if not self.running:
                    break
                logging.warning(f"Ağ dinleyicide bir hata oluştu: {e}")
                logging.info("Dinleyici 10 saniye içinde yeniden başlatılacak...")
                time.sleep(10)
        
        self.stop()

    def stop(self):
        """Tüm işlemleri güvenli bir şekilde durdurur ve son verileri API'ye gönderir."""
        if self.running:
            logging.info("Durdurma sinyali alındı. Son veriler gönderiliyor...")
            self.running = False
            time.sleep(2)
            self.send_data_to_api()

def check_permissions():
    """Programın root/yönetici yetkileriyle çalışıp çalışmadığını kontrol eder."""
    if os.name != 'nt' and os.geteuid() != 0:
        logging.error("Bu programın ağ trafiğini dinleyebilmesi için root yetkisi gereklidir.")
        print("Lütfen 'sudo python3 main.py' komutu ile çalıştırın.")
        sys.exit(1)

def select_interface() -> Optional[str]:
    """Kullanıcının dinlemek istediği ağ arayüzünü seçmesini sağlar."""
    try:
        interfaces = [iface.name for iface in scapy.get_working_ifaces()]
        if not interfaces:
            logging.warning("Kullanılabilir ağ arayüzü bulunamadı.")
            return None

        print("\nMevcut Ağ Arayüzleri:")
        for i, iface_name in enumerate(interfaces, 1):
            print(f"  {i}. {iface_name}")
        
        default_choice = 1
        choice_str = input(f"\nİzlenecek arayüz numarasını seçin [Varsayılan: {default_choice}]: ")
        
        choice = int(choice_str) if choice_str.isdigit() else default_choice
        
        return interfaces[choice - 1] if 0 < choice <= len(interfaces) else interfaces[0]
    except Exception as e:
        logging.warning(f"Arayüz seçimi sırasında bir hata oluştu, varsayılan arayüz kullanılacak. Hata: {e}")
        return None

def main():
    """Ana program fonksiyonu. Tüm süreci başlatır ve yönetir."""
    check_permissions()
    ensure_user_info()
    interface = select_interface()
    
    harvester = WANHarvester()
    
    def signal_handler(sig, frame):
        print("\nCTRL+C algılandı. Program güvenli bir şekilde kapatılıyor...")
        harvester.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    harvester.start_monitoring(interface=interface)
    
    logging.info("Program sonlandırıldı.")

if __name__ == "__main__":
    main()
