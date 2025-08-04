#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Project Tarassut - pasha.org.tr Projesi

Bu script, çoklu yöntemlerle IPv4 adreslerini toplar ve pasha.org.tr API'sine gönderir.
"""

import os
import sys
import json
import time
import signal
import logging
import threading
import subprocess
from dotenv import load_dotenv, set_key
from dotenv import dotenv_values
from datetime import datetime
from pathlib import Path
import socket
import struct
from datetime import datetime
from typing import Optional, List, Dict, Set
from collections import defaultdict
import re

try:
    import requests
except ImportError:
    print("HATA: Requests kütüphanesi bulunamadı.")
    print("Lütfen 'pip install requests' komutu ile kurun.")
    sys.exit(1)

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, UDP, TCP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("HATA: Scapy kütüphanesi bulunamadı.")
    print("Lütfen 'pip install scapy scapy[complete]' komutu ile kurun.")
    sys.exit(1)

# --- Yapılandırma ---
CONFIG = {
    "API_URL": "https://pasha.org.tr/api/tarassut",
    "SAVE_INTERVAL_SECONDS": 360, # 6 dakika
    "LOG_LEVEL": logging.INFO,
    "DNS_RESOLUTION_ENABLED": True,
    "NETWORK_DISCOVERY_ENABLED": True,
    "HTTP_ANALYSIS_ENABLED": True,
    "PASSIVE_DNS_ENABLED": True,
    "NETWORK_SCAN_INTERVAL": 900,  # 15 dakika
    "MAX_CONCURRENT_RESOLVES": 50,
}

# --- Loglama Kurulumu ---
logging.basicConfig(
    level=CONFIG["LOG_LEVEL"],
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def ensure_user_info():
    """Kullanıcı bilgileri alınır ve .env dosyasına yazılır"""
    dotenv_path = Path(".env")
    load_dotenv(dotenv_path)

    required_fields = {
        "USER_FULLNAME": "İsim Soyisim",
        "USER_USERNAME": "Kullanıcı Adı",
        "USER_EMAIL": "E-posta",
        "USER_LINKEDIN": "LinkedIn",
        "USER_GITHUB": "GitHub"
    }

    missing = [key for key in required_fields if not os.getenv(key)]

    if missing:
        print("Lütfen kullanıcı bilgilerinizi girin:")
        for key in missing:
            value = input(f"{required_fields[key]}: ").strip()
            set_key(dotenv_path, key, value)
    else:
        print("✓ Kullanıcı bilgileri bulundu.")


class AdvancedIPv4Harvester:
    """Gelişmiş IPv4 adres toplama sınıfı - çoklu yöntemlerle keşif"""

    def __init__(self):
        self.ipv4_addresses = set()  # Sadece benzersiz IPv4 adresleri
        self.running = False
        self.packet_count = 0
        self.lock = threading.Lock()
        self.dns_cache = {}  # DNS çözümleme cache'i

    def _add_ip(self, ip: str):
        """IPv4 adresini listeye ekle"""
        if not self._is_valid_ipv4(ip):
            return

        if self._is_private_ip(ip):
            return

        with self.lock:
            self.ipv4_addresses.add(ip)

    def _is_private_ip(self, ip: str) -> bool:
        """Yerel (private) IPv4 adreslerini filtrele"""
        try:
            parts = [int(part) for part in ip.split('.')]
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
        except ValueError:
            return False
        return False


    def _is_valid_ipv4(self, ip: str) -> bool:
        """IPv4 adres formatını kontrol et"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def _packet_handler(self, packet: scapy.packet.Packet):
        """Ana paket işleyici - tüm protokolleri analiz eder"""
        self.packet_count += 1
        
        if packet.haslayer(IP):
            self._analyze_ip_packet(packet)
        
        if packet.haslayer(DNS):
            self._analyze_dns_packet(packet)
            
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            self._analyze_http_packet(packet)

        if self.packet_count % 500 == 0:
            logging.info(
                f"İşlenen paket: {self.packet_count}, "
                f"Toplam IPv4: {len(self.ipv4_addresses)}"
            )

    def _analyze_ip_packet(self, packet):
        """IP paketlerini analiz et - sadece IP adreslerini topla"""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        self._add_ip(src_ip)
        self._add_ip(dst_ip)

    def _analyze_dns_packet(self, packet):
        """DNS paketlerini analiz et ve A kayıtlarından IP adreslerini çıkar"""
        if not CONFIG["PASSIVE_DNS_ENABLED"]:
            return
            
        dns = packet[DNS]
        
        if dns.qr == 1:
            if dns.ancount > 0:
                for i in range(dns.ancount):
                    rr = dns.an[i]
                    if rr.type == 1:
                        ip = rr.rdata
                        self._add_ip(ip)
                        logging.debug(f"DNS A kaydından IP: {ip}")

    def _analyze_http_packet(self, packet):
        """HTTP paketlerini analiz et ve Host başlıklarından IP çıkar"""
        if not CONFIG["HTTP_ANALYSIS_ENABLED"]:
            return
            
        try:
            if packet.haslayer(HTTPRequest):
                host = packet[HTTPRequest].Host
                if host:
                    domain = host.decode('utf-8') if isinstance(host, bytes) else str(host)
                    self._resolve_domain_async(domain)
        except Exception as e:
            logging.debug(f"HTTP analiz hatası: {e}")

    def _resolve_domain_async(self, domain: str):
        """Domain adını asenkron olarak çözümle - sadece IP'yi kaydet"""
        if domain in self.dns_cache:
            return
            
        def resolve():
            try:
                ip = socket.gethostbyname(domain)
                self.dns_cache[domain] = ip
                self._add_ip(ip)
            except socket.gaierror:
                pass
                
        threading.Thread(target=resolve, daemon=True).start()

    def _network_discovery_loop(self):
        """Periyodik network discovery"""
        while self.running:
            time.sleep(CONFIG["NETWORK_SCAN_INTERVAL"])
            if self.running and CONFIG["NETWORK_DISCOVERY_ENABLED"]:
                self._discover_local_network()

    def _discover_local_network(self):
        """Yerel ağı keşfet - sadece IP adreslerini topla"""
        logging.info("Yerel ağ keşfi başlatılıyor...")
        
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                gateway = result.stdout.split()[2]
                self._add_ip(gateway)
                
                network = '.'.join(gateway.split('.')[:-1]) + '.0/24'
                self._ping_sweep(network)
                
        except Exception as e:
            logging.debug(f"Network discovery hatası: {e}")

    def _ping_sweep(self, network: str):
        """Ping sweep ile aktif hostları bul - sadece IP adreslerini kaydet"""
        network_base = network.split('/')[0].rsplit('.', 1)[0]
        
        def ping_host(ip):
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, timeout=2)
                if result.returncode == 0:
                    self._add_ip(ip)
            except:
                pass
        
        threads = []
        for i in range(1, 51):
            ip = f"{network_base}.{i}"
            t = threading.Thread(target=ping_host, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
            
        for t in threads:
            t.join(timeout=5)

    def send_data_to_api(self):
        """Toplanan IPv4 adreslerini API'ye gönderir."""
        with self.lock:
            if not self.ipv4_addresses:
                logging.info("Gönderilecek yeni IP adresi bulunmuyor.")
                return
            ip_list = sorted(list(self.ipv4_addresses))

        logging.info(f"Toplanan {len(ip_list)} IPv4 adresi API'ye gönderiliyor...")

        try:
            user_info = dotenv_values(".env")
            data = {
                "user": {
                    "fullname": user_info.get("USER_FULLNAME", ""),
                    "username": user_info.get("USER_USERNAME", ""),
                    "email": user_info.get("USER_EMAIL", ""),
                    "linkedin": user_info.get("USER_LINKEDIN", ""),
                    "github": user_info.get("USER_GITHUB", "")
                },
                "source": "main.py",
                "collected_at": datetime.now().isoformat(),
                "ipv4_addresses": ip_list
            }

            headers = {"Content-Type": "application/json"}
            response = requests.post(CONFIG["API_URL"], json=data, headers=headers, timeout=30)

            if response.status_code == 201:
                inserted_id = response.json().get("insertedId", "N/A")
                logging.info(f"Veri başarıyla gönderildi. Kayıt ID: {inserted_id}")
                with self.lock:
                    self.ipv4_addresses.clear()
            else:
                logging.error(f"API'ye veri gönderilemedi. Durum Kodu: {response.status_code}, Yanıt: {response.text}")

        except requests.exceptions.RequestException as e:
            logging.error(f"API isteği sırasında bir hata oluştu: {e}")
        except Exception as e:
            logging.error(f"Veri gönderme sırasında beklenmedik bir hata oluştu: {e}")

    def _auto_save_loop(self):
        """Periyodik gönderme döngüsü"""
        while self.running:
            time.sleep(CONFIG["SAVE_INTERVAL_SECONDS"])
            if self.running:
                self.send_data_to_api()

    def start_monitoring(self, interface: Optional[str]):
        """IPv4 keşif sistemini başlat"""
        self.running = True
        
        save_thread = threading.Thread(target=self._auto_save_loop, daemon=True)
        save_thread.start()
        
        if CONFIG["NETWORK_DISCOVERY_ENABLED"]:
            discovery_thread = threading.Thread(target=self._network_discovery_loop, daemon=True)
            discovery_thread.start()

        print("\n" + "=" * 70)
        print("         GELİŞMİŞ IPv4 KEŞİF SİSTEMİ BAŞLATILDI")
        print(f"           (pasha.org.tr advanced discovery)")
        print("=" * 70)
        print(f"Aktif özellikler:")
        print(f"  ✓ Ağ trafiği dinleme")
        print(f"  {'✓' if CONFIG['PASSIVE_DNS_ENABLED'] else '✗'} Pasif DNS analizi")
        print(f"  {'✓' if CONFIG['HTTP_ANALYSIS_ENABLED'] else '✗'} HTTP Host analizi")
        print(f"  {'✓' if CONFIG['NETWORK_DISCOVERY_ENABLED'] else '✗'} Aktif network keşfi")
        print(f"  ✓ Veriler pasha.org.tr API'sine gönderiliyor")
        logging.info(f"API URL: {CONFIG['API_URL']}")
        logging.info(f"İzlenen arayüz: {interface or 'Tüm Arayüzler'}")
        print("=" * 70 + "\n")

        try:
            scapy.sniff(
                iface=interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except (PermissionError, OSError):
            logging.error("HATA: Ağ arayüzünü dinleme yetkiniz yok. Yönetici olarak çalıştırın.")
        except Exception as e:
            logging.critical(f"Beklenmedik bir hata oluştu: {e}")
        finally:
            self.stop()

    def stop(self):
        """İzlemeyi durdur ve son gönderim yap"""
        if self.running:
            logging.info("Durdurma sinyali alındı, son gönderim yapılıyor...")
            self.running = False
            self.send_data_to_api()

def check_permissions():
    """Root yetki kontrolü"""
    if os.name != 'nt' and os.geteuid() != 0:
        logging.error("Bu program root yetkisi gerektirir. Lütfen 'sudo' ile çalıştırın.")
        sys.exit(1)

def select_interface() -> Optional[str]:
    """Ağ arayüzü seçimi"""
    try:
        interfaces: List[str] = scapy.get_if_list()
        print("\nMevcut Ağ Arayüzleri:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        print("  0. Tüm Arayüzler (Varsayılan)")
        choice_str = input(f"\nİzlenecek arayüzü seçin [0-{len(interfaces)}]: ")
        choice = int(choice_str)
        return interfaces[choice - 1] if 0 < choice <= len(interfaces) else None
    except Exception:
        logging.info("Arayüz seçilemedi. Tüm arayüzler dinlenecek.")
        return None

def main():
    """Ana program"""
    check_permissions()
    ensure_user_info()
    interface = select_interface()
    
    harvester = AdvancedIPv4Harvester()
    
    def signal_handler(sig, frame):
        harvester.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    harvester.start_monitoring(interface)

if __name__ == "__main__":
    main()
