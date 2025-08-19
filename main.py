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
    Detaylı loglama sistemini kurar.
    """
    # Log dosyası adı
    log_filename = f"tarassut_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    # Formatter oluştur
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File handler
    file_handler = logging.FileHandler(log_filename, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Console handler (sadece önemli mesajlar için)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    # Root logger yapılandır
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[file_handler, console_handler],
        force=True
    )
    
    print(f"✅ Detaylı loglar {log_filename} dosyasına yazılıyor...")
    logging.info(f"Logging sistemi başlatıldı - Log dosyası: {log_filename}")
    
    return log_filename

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
        try:
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
                                    logging.debug(f"Yeni DNS eşleşmesi: {ip_address} -> {domain}")
                                    
                    except Exception as e:
                        logging.warning(f"DNS kaydı işlenirken hata: {e}")
        except Exception as e:
            logging.error(f"Paket işleme hatası: {e}", exc_info=True)

    # --- API Veri Gönderimi ---
    def send_data_to_api(self):
        """Toplanan DNS verilerini API'ye gönderir."""
        logging.info("=== API VERİ GÖNDERİMİ BAŞLADI ===")
        
        api_url = self.config.get('API', 'url')
        logging.info(f"API URL: {api_url}")
        
        with self.lock:
            if not self.ip_to_domains:
                logging.warning("Gönderilecek veri yok, işlem sonlandırılıyor")
                return
            
            ip_mappings_list = [
                {"ip": ip, "domains": sorted(list(domains))}
                for ip, domains in self.ip_to_domains.items()
            ]
            total_domains = sum(len(domains) for domains in self.ip_to_domains.values())
        
        total_ips = len(ip_mappings_list)
        
        logging.info(f"Gönderilecek veri: {total_ips} IP adresi, {total_domains} domain")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] API'ye gönderiliyor: {total_ips} IP adresi, {total_domains} domain.")

        try:
            # Kullanıcı bilgilerini al
            user_info = dotenv_values(".env")
            logging.debug(f"Kullanıcı bilgileri alındı: {list(user_info.keys())}")
            
            base_payload = {
                "user": {
                    "fullname": user_info.get("USER_FULLNAME", ""),
                    "username": user_info.get("USER_USERNAME", ""),
                    "email": user_info.get("USER_EMAIL", ""),
                    "linkedin": user_info.get("USER_LINKEDIN", ""),
                    "github": user_info.get("USER_GITHUB", "")
                },
                "source": "main.py (DNS-Logger)",
                "collected_at": datetime.now().isoformat(),
                "ip_mappings": ip_mappings_list
            }
            
            logging.debug(f"Base payload oluşturuldu - kullanıcı: {base_payload['user']['username']}")

            # Payload boyutunu kontrol et
            import json
            payload_json = json.dumps(base_payload)
            payload_size = len(payload_json.encode('utf-8'))
            max_size = 1 * 1024 * 1024  # 1MB (nginx limitine uygun)
            
            logging.info(f"Payload boyutu: {payload_size / (1024*1024):.2f} MB (Limit: {max_size / (1024*1024):.2f} MB)")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Payload boyutu: {payload_size / (1024*1024):.2f} MB")
            
            # İlk birkaç karakter log'a yaz (debug için)
            logging.debug(f"Payload preview (ilk 500 karakter): {payload_json[:500]}...")
            
            if payload_size > max_size:
                logging.warning(f"Payload çok büyük ({payload_size / (1024*1024):.2f} MB), parçalara bölünecek")
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Payload çok büyük ({payload_size / (1024*1024):.2f} MB), parçalara bölünüyor...")
                self._send_chunked_data(base_payload, ip_mappings_list)
            else:
                logging.info("Payload boyutu uygun, tek seferde gönderiliyor")
                self._send_single_payload(base_payload)

        except Exception as e:
            logging.error(f"Veri gönderme sırasında beklenmedik hata: {str(e)}", exc_info=True)
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HATA: {str(e)}")
        
        logging.info("=== API VERİ GÖNDERİMİ TAMAMLANDI ===\n")

    def _send_single_payload(self, payload):
        """Tek payload olarak veri gönderir."""
        logging.info("--- TEK PAYLOAD GÖNDERİMİ BAŞLADI ---")
        
        api_url = self.config.get('API', 'url')
        headers = {"Content-Type": "application/json"}
        
        logging.info(f"İstek URL: {api_url}")
        logging.info(f"İstek Headers: {headers}")
        logging.info(f"Payload IP mapping sayısı: {len(payload.get('ip_mappings', []))}")
        
        try:
            logging.info("HTTP POST isteği gönderiliyor...")
            response = requests.post(api_url, json=payload, headers=headers, timeout=60)
            
            logging.info(f"HTTP Response alındı - Status Code: {response.status_code}")
            logging.info(f"Response Headers: {dict(response.headers)}")
            
            # Response content'i kontrol et
            content_type = response.headers.get('content-type', '').lower()
            logging.info(f"Response Content-Type: {content_type}")
            
            # Response boyutunu log'la
            response_size = len(response.content)
            logging.info(f"Response boyutu: {response_size} bytes")
            
            # Response'un ilk kısmını log'la
            response_preview = response.text[:500] + "..." if len(response.text) > 500 else response.text
            logging.debug(f"Response preview (ilk 500 karakter): {response_preview}")
            
            if response.status_code == 201:
                logging.info("✅ Veri başarıyla gönderildi!")
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Veri başarıyla gönderildi. Bellek sıfırlandı.")
                with self.lock:
                    self.ip_to_domains.clear()
            elif response.status_code == 413:
                # 413 hatası - payload çok büyük, önbelleği temizle ve chunk'lara böl
                logging.warning("⚠️ 413 Payload Too Large hatası - önbellek temizleniyor ve chunk sistemine geçiliyor")
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 413 Payload çok büyük hatası - veriler chunk'lara bölünecek")
                
                # Önbelleği temizle
                with self.lock:
                    self.ip_to_domains.clear()
                
                # Chunk sistemini etkinleştir (bir sonraki döngüde daha küçük parçalar gönderilecek)
                logging.info("Chunk sistemi etkinleştirildi - bir sonraki döngüde daha küçük parçalar gönderilecek")
                
            else:
                # HTML yanıtını kontrol et
                is_html = "<!DOCTYPE html>" in response.text or "<html" in response.text.lower()
                logging.error(f"❌ API Hatası - Status: {response.status_code}")
                logging.error(f"HTML yanıtı mı: {is_html}")
                
                if is_html:
                    logging.error("HTML yanıtı alındı - muhtemelen yanlış endpoint veya nginx yapılandırma sorunu")
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] API Hatası: {response.status_code} - HTML yanıtı alındı (endpoint sorunu olabilir)")
                else:
                    logging.error(f"API Error Response: {response_preview}")
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] API Hatası: {response.status_code} - {response_preview}")
                
                # Diğer hatalar için de önbelleği temizle (veri kaybını önlemek için)
                if response.status_code in [400, 401, 403, 404, 422]:  # İstemci hataları
                    logging.warning(f"İstemci hatası ({response.status_code}) - önbellek temizleniyor")
                    with self.lock:
                        self.ip_to_domains.clear()
                
        except requests.exceptions.Timeout as e:
            logging.error(f"❌ Timeout hatası: {str(e)}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Timeout hatası: {e}")
        except requests.exceptions.ConnectionError as e:
            logging.error(f"❌ Bağlantı hatası: {str(e)}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Bağlantı hatası: {e}")
        except requests.exceptions.RequestException as e:
            logging.error(f"❌ Request hatası: {str(e)}", exc_info=True)
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Request hatası: {e}")
        except Exception as e:
            logging.error(f"❌ Beklenmedik hata: {str(e)}", exc_info=True)
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Beklenmedik hata: {e}")
        
        logging.info("--- TEK PAYLOAD GÖNDERİMİ TAMAMLANDI ---\n")

    def _send_chunked_data(self, base_payload, ip_mappings_list):
        """Büyük veriyi parçalara bölerek gönderir."""
        chunk_size = 100  # Her chunk'ta maksimum 100 IP mapping (nginx limiti için küçültüldü)
        chunks = [ip_mappings_list[i:i + chunk_size] for i in range(0, len(ip_mappings_list), chunk_size)]
        
        logging.info(f"Chunk sistemi: {len(ip_mappings_list)} IP mapping, {len(chunks)} parçaya bölündü")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {len(chunks)} parçaya bölündü, gönderiliyor...")
        
        success_count = 0
        for i, chunk in enumerate(chunks):
            chunk_payload = base_payload.copy()
            chunk_payload["ip_mappings"] = chunk
            
            # Chunk boyutunu kontrol et
            import json
            chunk_size_bytes = len(json.dumps(chunk_payload).encode('utf-8'))
            logging.info(f"Chunk {i+1} boyutu: {chunk_size_bytes / 1024:.2f} KB")
            
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Parça {i+1}/{len(chunks)} gönderiliyor ({len(chunk)} IP, {chunk_size_bytes / 1024:.2f} KB)...")
            
            if self._send_single_chunk(chunk_payload, i+1, len(chunks)):
                success_count += 1
            else:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Parça {i+1} gönderilemedi!")
        
        if success_count == len(chunks):
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Tüm parçalar başarıyla gönderildi. Bellek sıfırlandı.")
            with self.lock:
                self.ip_to_domains.clear()
        else:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {success_count}/{len(chunks)} parça gönderildi. Bellek korunuyor.")
            # Kısmi başarı durumunda da belleği temizle (veri kaybını önlemek için)
            if success_count > 0:
                logging.warning(f"Kısmi başarı: {success_count}/{len(chunks)} - bellek yine de temizleniyor")
                with self.lock:
                    self.ip_to_domains.clear()

    def _send_single_chunk(self, payload, chunk_num, total_chunks):
        """Tek bir chunk gönderir."""
        logging.info(f"--- CHUNK {chunk_num}/{total_chunks} GÖNDERİMİ BAŞLADI ---")
        
        api_url = self.config.get('API', 'url')
        headers = {"Content-Type": "application/json"}
        
        logging.info(f"Chunk URL: {api_url}")
        logging.info(f"Chunk {chunk_num} IP mapping sayısı: {len(payload.get('ip_mappings', []))}")
        
        try:
            logging.info(f"Chunk {chunk_num} HTTP POST isteği gönderiliyor...")
            response = requests.post(api_url, json=payload, headers=headers, timeout=60)
            
            logging.info(f"Chunk {chunk_num} Response - Status: {response.status_code}")
            
            # Response content'i kontrol et
            response_size = len(response.content)
            logging.info(f"Chunk {chunk_num} Response boyutu: {response_size} bytes")
            
            if response.status_code == 201:
                logging.info(f"✅ Chunk {chunk_num} başarıyla gönderildi")
                return True
            else:
                # HTML yanıtını kontrol et
                is_html = "<!DOCTYPE html>" in response.text or "<html" in response.text.lower()
                logging.error(f"❌ Chunk {chunk_num} hatası - Status: {response.status_code}")
                logging.error(f"Chunk {chunk_num} HTML yanıtı mı: {is_html}")
                
                response_preview = response.text[:200] + "..." if len(response.text) > 200 else response.text
                
                if is_html:
                    logging.error(f"Chunk {chunk_num} HTML yanıtı alındı")
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Parça {chunk_num} hatası: {response.status_code} - HTML yanıtı alındı")
                else:
                    logging.error(f"Chunk {chunk_num} Error Response: {response_preview}")
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Parça {chunk_num} hatası: {response.status_code} - {response_preview}")
                
                return False
                
        except requests.exceptions.Timeout as e:
            logging.error(f"❌ Chunk {chunk_num} timeout hatası: {str(e)}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Parça {chunk_num} timeout hatası: {e}")
            return False
        except requests.exceptions.ConnectionError as e:
            logging.error(f"❌ Chunk {chunk_num} bağlantı hatası: {str(e)}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Parça {chunk_num} bağlantı hatası: {e}")
            return False
        except requests.exceptions.RequestException as e:
            logging.error(f"❌ Chunk {chunk_num} request hatası: {str(e)}", exc_info=True)
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Parça {chunk_num} request hatası: {e}")
            return False
        except Exception as e:
            logging.error(f"❌ Chunk {chunk_num} beklenmedik hata: {str(e)}", exc_info=True)
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Parça {chunk_num} beklenmedik hata: {e}")
            return False
        finally:
            logging.info(f"--- CHUNK {chunk_num}/{total_chunks} GÖNDERİMİ TAMAMLANDI ---\n")

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
        
        logging.info(f"Dinleyici yapılandırması:")
        logging.info(f"  - Kaydetme aralığı: {save_interval} saniye")
        logging.info(f"  - BPF filtresi: {bpf_filter}")
        
        self.running = True
        threading.Thread(target=self._auto_save_loop, daemon=True).start()
        logging.info("✅ Otomatik kaydetme thread'i başlatıldı")
        
        print("Ağ trafiği dinleyicisi başlatıldı. DNS eşleşmeleri dinleniyor...")
        print(f"Toplanan veriler her {save_interval} saniyede bir API'ye gönderilecek.")
        print("Durdurmak için Ctrl+C tuşlarına basın.")
        
        try:
            logging.info("Scapy sniff başlatılıyor...")
            sniff(filter=bpf_filter, prn=self._packet_callback, store=0, stop_filter=lambda p: not self.running)
        except PermissionError:
            logging.error("İzin hatası! Root yetkileri gerekli.")
            print("Lütfen 'sudo python3 main.py' komutu ile çalıştırın.")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Dinleme sırasında hata: {str(e)}", exc_info=True)
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
    print("🔧 Project Tarassut başlatılıyor...")
    
    # Detaylı logging sistemini başlat
    log_filename = setup_logging()
    logging.info("=== PROJECT TARASSUT BAŞLATILDI ===")
    logging.info(f"Python sürümü: {sys.version}")
    logging.info(f"Çalışma dizini: {os.getcwd()}")
    
    try:
        check_permissions()
        logging.info("✅ İzin kontrolü başarılı")
        
        ensure_user_info()
        logging.info("✅ Kullanıcı bilgileri kontrol edildi")
        
        logger = DNSLogger(CONFIG)
        logging.info("✅ DNS Logger oluşturuldu")
        
        def signal_handler(sig, frame):
            logging.info(f"Signal alındı: {sig}")
            logger.stop()
            print("\nProgram sonlandırılıyor...")
            logging.info("Program sonlandırıldı")
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        logging.info("DNS dinleyici başlatılıyor...")
        logger.start()
        
    except Exception as e:
        logging.error(f"Ana program hatası: {str(e)}", exc_info=True)
        print(f"❌ Kritik hata: {e}")
    finally:
        logging.info("=== PROJECT TARASSUT SONLANDIRILDI ===")
        print(f"📋 Detaylı loglar {log_filename} dosyasında saklandı.")


# --- İzin Kontrolü ---
def check_permissions():
    """Programın root/yönetici yetkileriyle çalışıp çalışmadığını kontrol eder."""
    if os.name != 'nt' and os.geteuid() != 0:
        logging.error("Bu programın ağ trafiğini dinleyebilmesi için root yetkisi gereklidir.")
        print("Lütfen 'sudo python3 test.py' komutu ile çalıştırın.")
        sys.exit(1)

if __name__ == "__main__":
    main()
