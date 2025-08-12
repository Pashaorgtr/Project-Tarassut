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

import logging
from datetime import datetime
import os
from dotenv import load_dotenv, set_key, dotenv_values
from pathlib import Path
import signal
import sys
import threading
import time
from collections import defaultdict
import configparser

try:
    import requests
except ImportError:
    print("HATA: Gerekli 'requests' kütüphanesi bulunamadı.")
    print("Lütfen 'pip install requests' komutu ile kurun.")
    sys.exit(1)

try:
    from scapy.all import sniff, DNS
except ImportError:
    print("HATA: Gerekli 'scapy' kütüphanesi bulunamadı.")
    print("Lütfen 'pip install scapy' komutu ile kurun.")
    sys.exit(1)


# --- Yapılandırma Yöneticisi ---
def load_config():
    """
    config.ini dosyasını okur. Eğer dosya yoksa, varsayılan ayarlarla oluşturur.
    """
    config_file = 'config.ini'
    config = configparser.ConfigParser()

    if not os.path.exists(config_file):
        print(f"'{config_file}' bulunamadı. Varsayılan ayarlarla oluşturuluyor...")
        config['API'] = {
            'url': 'https://pasha.org.tr/api/tarassut',
            'save_interval_seconds': '300'
        }
        config['Logging'] = {
            'file': 'domain_ip_mappings.log',
            'level': 'INFO'
        }
        config['Sniffer'] = {
            'bpf_filter': 'udp port 53 or tcp port 53'
        }
        with open(config_file, 'w', encoding='utf-8') as f:
            config.write(f)
    
    config.read(config_file, encoding='utf-8')
    return config


# --- Global Yapılandırma ---
CONFIG = load_config()


# --- Loglama Kurulumu ---
def setup_logging():
    """
    Loglama sistemini kurar. Bu haliyle loglama devre dışı bırakılmıştır.
    """
    logging.basicConfig(handlers=[logging.NullHandler()])

# --- Kullanıcı Bilgileri ---
def ensure_user_info():
    """
    Kullanıcı bilgilerinin (.env dosyasında) mevcut olduğunu kontrol eder.
    Eksik bilgi varsa, kullanıcıdan alınarak dosyaya yazılır.
    """
    dotenv_path = Path(".env")
    load_dotenv(dotenv_path)

    required_fields = {
        "USER_FULLNAME": "Tam Adınız",
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


# --- DNS Dinleyici Sınıfı ---
class DNSLogger:
    """
    Ağ trafiğini dinleyerek DNS kayıtlarını yakalayan, loglayan ve
    periyodik olarak merkezi API'ye gönderen sınıf.
    """
    # --- Kurucu Method ---
    def __init__(self, config):
        self.config = config
        self.ip_to_domains = defaultdict(set)
        self.lock = threading.Lock()
        self.running = False

    # --- Paket İşleyici ---
    def _packet_callback(self, packet):
        """Yakalanan her paket için çağrılır ve DNS verilerini işler."""
        if packet.haslayer(DNS) and packet[DNS].qr == 1 and packet[DNS].ancount > 0:
            for i in range(packet[DNS].ancount):
                try:
                    dns_record = packet[DNS].an[i]
                    if dns_record.type == 1:  # 1: A kaydı (IPv4)
                        domain = dns_record.rrname.decode('utf-8').rstrip('.')
                        ip_address = dns_record.rdata

                        with self.lock:
                            if domain not in self.ip_to_domains[ip_address]:
                                self.ip_to_domains[ip_address].add(domain)
                except Exception as e:
                    logging.warning(f"DNS kaydı işlenirken hata: {e}")

    # --- API Veri Gönderimi ---
    def send_data_to_api(self):
        """Toplanan DNS verilerini API'ye gönderir."""
        api_url = self.config.get('API', 'url')
        with self.lock:
            if not self.ip_to_domains:
                return
            
            ip_mappings_list = [
                {"ip": ip, "domains": sorted(list(domains))}
                for ip, domains in self.ip_to_domains.items()
            ]
            total_domains = sum(len(domains) for domains in self.ip_to_domains.values())
        
        total_ips = len(ip_mappings_list)
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] API'ye gönderiliyor: {total_ips} IP adresi, {total_domains} domain.")

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
                "source": "test.py (DNS-Logger)",
                "collected_at": datetime.now().isoformat(),
                "ip_mappings": ip_mappings_list
            }

            headers = {"Content-Type": "application/json"}
            response = requests.post(api_url, json=payload, headers=headers, timeout=30)

            if response.status_code == 201:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Veri başarıyla gönderildi. Bellek sıfırlandı.")
                with self.lock:
                    self.ip_to_domains.clear()
            else:
                logging.error(f"API'ye veri gönderilemedi. Durum Kodu: {response.status_code}, Yanıt: {response.text}")

        except requests.exceptions.RequestException as e:
            logging.error(f"API bağlantı hatası: {e}")
        except Exception as e:
            logging.error(f"Veri gönderme sırasında beklenmedik bir hata oluştu: {e}")

    # --- Otomatik Kaydetme Döngüsü ---
    def _auto_save_loop(self):
        """Belirlenen aralıklarla API'ye veri gönderimini tetikler."""
        save_interval = self.config.getint('API', 'save_interval_seconds', fallback=300)
        while self.running:
            time.sleep(save_interval)
            if self.running:
                self.send_data_to_api()

    # --- Dinleyici Başlatma ---
    def start(self):
        """Dinleyiciyi ve periyodik veri gönderimini başlatır."""
        save_interval = self.config.getint('API', 'save_interval_seconds', fallback=300)
        bpf_filter = self.config.get('Sniffer', 'bpf_filter', fallback='udp port 53 or tcp port 53')
        
        self.running = True
        threading.Thread(target=self._auto_save_loop, daemon=True).start()
        
        print("Ağ trafiği dinleyicisi başlatıldı. DNS eşleşmeleri dinleniyor...")
        print(f"Toplanan veriler her {save_interval} saniyede bir API'ye gönderilecek.")
        print("Durdurmak için Ctrl+C tuşlarına basın.")
        
        try:
            sniff(filter=bpf_filter, prn=self._packet_callback, store=0, stop_filter=lambda p: not self.running)
        except PermissionError:
            logging.error("\n[HATA] İzin Hatası! Bu betiği Yönetici veya root yetkileriyle çalıştırmalısınız.")
            print("Lütfen 'sudo python3 test.py' komutu ile çalıştırın.")
            sys.exit(1)
        except Exception as e:
            logging.error(f"\nDinleme sırasında bir hata oluştu: {e}")
            self.running = False

    # --- Dinleyici Durdurma ---
    def stop(self):
        """Dinleyiciyi durdurur ve son verileri gönderir."""
        if self.running:
            print("\nDurdurma sinyali alındı. Son veriler gönderiliyor...")
            self.running = False
            time.sleep(2)
            self.send_data_to_api()


# --- Ana Program ---
def main():
    """Ana fonksiyon. Tüm süreci başlatır ve yönetir."""
    setup_logging()
    check_permissions()
    ensure_user_info()
    
    logger = DNSLogger(CONFIG)
    
    def signal_handler(sig, frame):
        logger.stop()
        print("\nProgram sonlandırılıyor...")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.start()
    
    logging.info("Program sonlandırıldı.")


# --- İzin Kontrolü ---
def check_permissions():
    """Programın root/yönetici yetkileriyle çalışıp çalışmadığını kontrol eder."""
    if os.name != 'nt' and os.geteuid() != 0:
        logging.error("Bu programın ağ trafiğini dinleyebilmesi için root yetkisi gereklidir.")
        print("Lütfen 'sudo python3 test.py' komutu ile çalıştırın.")
        sys.exit(1)

if __name__ == "__main__":
    main()
