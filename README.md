# Project Tarassut

**Pasha - Advanced Internet Search Projesi için Gönüllü Veri Toplama Aracı**

[![Python Sürümü](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![Katkıda Bulun](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

## Proje Hakkında

**Project Tarassut**, [pasha.org.tr](https://pasha.org.tr) tarafından yürütülen "Pasha - Advanced Internet Search" projesine destek olmak amacıyla geliştirilmiş, açık kaynaklı bir veri toplama aracıdır. Bu araç, gönüllü kullanıcıların kendi bilgisayarlarında çalıştırarak internet trafiğinde tespit ettikleri genel (public) IPv4 adreslerini anonim olarak pasha.org.tr API'sine göndermelerini sağlar.

Toplanan bu veriler, internetin anlık bir haritasını çıkarmak, siber güvenlik araştırmaları yapmak ve internetin genel sağlığını ve canlılığını analiz etmek için kullanılacaktır. Katkılarınız, daha güvenli ve şeffaf bir internet ortamı oluşturma hedefimize ulaşmamızda kritik bir rol oynamaktadır.

## Nasıl Çalışır?

Project Tarassut, bilgisayarınızdaki ağ trafiğini dinleyerek (örneğin, ziyaret ettiğiniz web siteleri, çevrimiçi oyunlar, DNS sorguları vb.) genel IPv4 adreslerini tespit eder. Araç, yalnızca **genel (public) IP adreslerini** toplar ve yerel (private) ağınızdaki (192.168.x.x, 10.x.x.x vb.) veya kişisel cihazlarınıza ait IP adreslerini **toplamaz**.

Toplanan IP adresleri, belirli aralıklarla pasha.org.tr API'sine güvenli bir şekilde gönderilir. Gönderilen veriler, herhangi bir kişisel bilgi veya trafik içeriği içermez; yalnızca tespit edilen IPv4 adreslerini ve toplandığı zamanı içerir.

## Kurulum ve Kullanım

Projeyi bilgisayarınıza kurmak ve gönüllü olmak için aşağıdaki adımları izleyin:

**1. Projeyi Klonlayın:**

```bash
git clone https://github.com/Pashaorgtr/Project-Tarassut.git
cd Project-Tarassut
```

**2. Gerekli Kütüphaneleri Yükleyin:**

Programın çalışması için gerekli olan Python kütüphanelerini yükleyin.

```bash
pip install -r requirements.txt
```

**3. Kullanıcı Bilgilerini Yapılandırın:**

Programı ilk kez çalıştırdığınızda, sizden bazı temel kullanıcı bilgileri istenecektir. Bu bilgiler, katkılarınızı pasha.org.tr'de (isteğe bağlı olarak) sergilemek ve projenin gönüllü topluluğunu tanımak amacıyla kullanılır.

```bash
sudo python3 main.py
```

Program sizden aşağıdaki bilgileri girmenizi isteyecektir:
*   İsim Soyisim
*   Kullanıcı Adı
*   E-posta
*   LinkedIn Profil URL'si
*   GitHub Profil URL'si

Bu bilgiler, projenizin ana dizininde oluşturulan `.env` dosyasında saklanır ve yalnızca API'ye veri gönderilirken kullanılır.

**4. Programı Çalıştırın:**

Kurulum tamamlandıktan sonra, programı root (yönetici) yetkileriyle çalıştırın. Program, ağ arayüzlerini dinlemek için bu yetkilere ihtiyaç duyar.

```bash
sudo python3 main.py
```

Program çalışmaya başladığında, mevcut ağ arayüzlerinden birini seçmeniz istenecektir. Genellikle varsayılan seçeneği (Tüm Arayüzler) seçmek yeterlidir.

## Windows Kullanıcıları İçin Uyarı

🪟 **Windows kullanıyorsanız**, Project Tarassut aracının ağ trafiğini dinleyebilmesi için sisteminizde **Npcap** yüklü olmalıdır. Aksi takdirde program çalışırken hatalar alabilirsiniz.

### 🔧 Npcap Nasıl Kurulur?

1. Npcap'in en güncel sürümünü aşağıdaki bağlantıdan indirin:
   👉 [Npcap 1.83 İndir](https://npcap.com/dist/npcap-1.83.exe)

2. İndirme tamamlandıktan sonra, yükleyiciyi çalıştırarak varsayılan ayarlarla kurun. "Install Npcap in WinPcap API-compatible Mode" seçeneğini **işaretlemeyi unutmayın.**

3. Kurulum hakkında detaylı yardım isterseniz aşağıdaki videoyu izleyebilirsiniz:
   🎥 [Npcap Kurulum Videosu](https://www.youtube.com/watch?v=lOcf0BylnO4)

> 💡 **Not:** Npcap, Windows üzerinde `scapy` ve benzeri ağ dinleme kütüphanelerinin düzgün çalışması için gereklidir. Linux kullanıcılarının bu adıma ihtiyacı yoktur.

## Yasal Sorumluluk ve Uyarılar

*   **Yasalara Uygunluk:** Bu aracı kullanırken bulunduğunuz ülkenin veya bölgenin yasalarına ve yönetmeliklerine uymak tamamen sizin sorumluluğunuzdadır. Yasa dışı faaliyetler için kullanılması kesinlikle yasaktır.
*   **Veri Gizliliği:** Project Tarassut, kişisel verilerinizi veya ağ trafiğinizin içeriğini (örneğin, şifreler, mesajlar) toplamaz. Yalnızca genel IPv4 adreslerini hedefler. Ancak, programın doğası gereği ağ trafiğinizi izlediğini unutmayın.
*   **Sorumluluk Reddi:** Bu aracın kullanımından kaynaklanabilecek doğrudan veya dolaylı hiçbir zarardan proje geliştiricileri veya pasha.org.tr sorumlu tutulamaz. Aracı kullanmaya başlayarak bu şartları kabul etmiş sayılırsınız.
*   **Açık Kaynak:** Bu proje tamamen şeffaftır. Kodun tamamını inceleyebilir, nasıl çalıştığını analiz edebilir ve güvenlik denetimleri yapabilirsiniz.

## Projeye Katkıda Bulunma

Bu proje, topluluk katkılarıyla büyür. Katkıda bulunmak isterseniz:

1.  Projeyi "Fork" edin.
2.  Yeni bir "Branch" oluşturun.
3.  Değişikliklerinizi yapın ve "Commit" edin.
4.  "Branch"inizi "Push" edin.
5.  Bir "Pull Request" (PR) oluşturun.

Tüm katkılarınız için şimdiden teşekkür ederiz!
