"""
AutoRedTeam - MITRE ATT&CK Mapper & Remediation Advisor.

Bulgu kategorilerini MITRE ATT&CK teknikleriyle esler ve kategori bazli
gercek remediation (duzeltme) onerileri sunar.
"""

from __future__ import annotations

from typing import Any, Dict, List

# ── MITRE ATT&CK Eslemesi ───────────────────────────────────────────────────
# Kategori -> (teknik_id, teknik_adi, taktik)

ATTACK_MAP: Dict[str, tuple] = {
    "Weak Default Credentials": (
        "T1078.001", "Valid Accounts: Default Accounts", "Initial Access / Persistence",
    ),
    "Backdoor Exploitation": (
        "T1505", "Server Software Component (Backdoor)", "Persistence",
    ),
    "Privilege Escalation": (
        "T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation",
    ),
    "SQL Injection": (
        "T1190", "Exploit Public-Facing Application", "Initial Access",
    ),
    "Command Injection": (
        "T1059", "Command and Scripting Interpreter", "Execution",
    ),
    "Cross-Site Scripting": (
        "T1059.007", "JavaScript/JScript", "Execution",
    ),
    "Local File Inclusion": (
        "T1005", "Data from Local System", "Collection",
    ),
    "File Upload": (
        "T1505.003", "Web Shell", "Persistence",
    ),
    "Remote Code Execution (CVE-2004-2687)": (
        "T1190", "Exploit Public-Facing Application", "Initial Access",
    ),
    "Remote Code Execution (CVE-2007-2447)": (
        "T1190", "Exploit Public-Facing Application", "Initial Access",
    ),
    "Remote Code Execution (Ruby DRb)": (
        "T1190", "Exploit Public-Facing Application", "Initial Access",
    ),
    "Backdoor Exploitation (CVE-2011-2523)": (
        "T1505", "Server Software Component", "Persistence",
    ),
    "Backdoor Exploitation (CVE-2010-2075)": (
        "T1505", "Server Software Component", "Persistence",
    ),
    "Unauthenticated File Copy (CVE-2015-3306)": (
        "T1190", "Exploit Public-Facing Application", "Initial Access",
    ),
    "Insecure Java RMI Registry (Deserialization Surface)": (
        "T1190", "Exploit Public-Facing Application", "Initial Access",
    ),
    "VNC Weak/Null Authentication": (
        "T1078", "Valid Accounts", "Initial Access",
    ),
    "Apache Tomcat Manager Default Credentials": (
        "T1078.001", "Valid Accounts: Default Accounts", "Initial Access",
    ),
    "Broken Access Control": (
        "T1190", "Exploit Public-Facing Application", "Initial Access",
    ),
    "Weak Default Credentials (Database)": (
        "T1078.001", "Valid Accounts: Default Accounts", "Initial Access",
    ),
    "Old Software Version": (
        "T1592.002", "Gather Victim Host Information: Software", "Reconnaissance",
    ),
    "Known vulnerable service version": (
        "T1592.002", "Gather Victim Host Information: Software", "Reconnaissance",
    ),
}

DEFAULT_ATTACK = ("T1190", "Exploit Public-Facing Application", "Initial Access")


def get_attack(category: str) -> Dict[str, str]:
    """Kategori icin ATT&CK teknik bilgisi dondurur."""
    tech_id, tech_name, tactic = ATTACK_MAP.get(category, DEFAULT_ATTACK)
    return {"technique_id": tech_id, "technique": tech_name, "tactic": tactic}


# ── Gercek Remediation ──────────────────────────────────────────────────────

REMEDIATION_MAP: Dict[str, str] = {
    "Weak Default Credentials": (
        "Tum varsayilan hesaplarin sifrelerini guclu, benzersiz degerlerle "
        "degistirin; varsayilan/kullanilmayan hesaplari devre disi birakin. "
        "MFA uygulayin ve parola politikasi (uzunluk + karmasiklik) zorunlu kilin. "
        "Basarisiz giris denemelerini izleyin ve hesap kilitleme uygulayin."
    ),
    "Backdoor Exploitation": (
        "Zafiyetli yazilim surumunu guncelleyin/degistirin (ornegin vsftpd, "
        "ingreslock). Bilinmeyen/arka kapili servisleri kaldirin. Dosya "
        "butunlugu izleme (FIM) ile beklenmeyen degisiklikleri tespit edin. "
        "Gereksiz servisleri kapatarak saldiri yuzeyini daraltin."
    ),
    "Privilege Escalation": (
        "SUID/SGID izinlerini denetleyin ve gereksiz olanlari kaldirin. "
        "sudoers yapilandirmasini en az yetki ilkesine gore sikilastirin "
        "((ALL) ALL gibi genis kurallari kaldirin). Kernel ve paketleri "
        "guncelleyin. GTFOBins suistimalini onlemek icin binary izinlerini "
        "gozden gecirin."
    ),
    "SQL Injection": (
        "Tum SQL sorgularinda parametreli (prepared) ifadeler kullanin. "
        "Girdi dogrulama ve beyaz liste uygulayin. Veritabani kullanicisina "
        "en az yetki verin (DROP/GRANT yok). WAF ile ek koruma saglayin. "
        "Hata mesajlarinda SQL detayi sizdirmayin."
    ),
    "Command Injection": (
        "Sistem komutlarina kullanici girdisini dogrudan aktarmayin; "
        "guvenli API'ler kullanin. Girdi dogrulama + beyaz liste uygulayin. "
        "Mumkunse shell yerine parametreli cagrilar kullanin. Uygulamayi "
        "dusuk yetkili kullanici olarak calistirin."
    ),
    "Cross-Site Scripting": (
        "Tum kullanici girdilerini cikti baglamina gore (HTML/JS/URL) kodlayin "
        "(output encoding). Content-Security-Policy (CSP) basligi ekleyin. "
        "Girdi dogrulama uygulayin. HttpOnly ve Secure cookie bayraklari kullanin."
    ),
    "Local File Inclusion": (
        "Kullanici kontrollu dosya yollarini dogrudan kullanmayin; beyaz liste "
        "ile izinli dosyalari sinirlayin. '..' ve null byte dizilerini engelleyin. "
        "Dosya islemlerini chroot/dizin kisitlamasi ile sinirlayin."
    ),
    "File Upload": (
        "Yuklenen dosyalari icerik turu ve uzantiya gore dogrulayin (beyaz liste). "
        "Dosyalari web kok dizini disinda saklayin. Yukleme dizininde betik "
        "calistirmayi devre disi birakin. WebDAV PUT/PROPFIND gibi gereksiz "
        "metotlari kapatmaya calisin."
    ),
    "Remote Code Execution (CVE-2004-2687)": (
        "distcc servisini guncelleyin veya yalnizca guvenilir agdan erisime "
        "izin verin. Kimlik dogrulama ve erisim kontrolu uygulayin. Gereksiz "
        "ise servisi devre disi birakin."
    ),
    "Remote Code Execution (CVE-2007-2447)": (
        "Samba'yi guncel surume yukseltin (CVE-2007-2447). 'username map "
        "script' ozelligini devre disi birakin. SMB erisimini kimlik dogrulama "
        "ve ag segmentasyonu ile sinirlayin."
    ),
    "Remote Code Execution (Ruby DRb)": (
        "Ruby DRb servisini kimlik dogrulama olmadan disariya acmayin. "
        "Bagli nesne sinirlarini kisitlayin veya servisi devre disi birakin. "
        "Guvenli olmayan deserialization'i engelleyin."
    ),
    "Backdoor Exploitation (CVE-2011-2523)": (
        "vsftpd'yi 2.3.4 disinda guvenli bir surume yukseltin. FTP yerine "
        "SFTP kullanin. Anonim FTP'yi devre disi birakin."
    ),
    "Backdoor Exploitation (CVE-2010-2075)": (
        "UnrealIRCd'yi guvenli surume yukseltin (3.2.8.1 backdoor icerir). "
        "Kaynaktan derleyerek dogrulanmis bir surum kullanin."
    ),
    "VNC Weak/Null Authentication": (
        "VNC'de guclu sifre kullanin veya erisimi SSH tuneli arkasina alin. "
        "Null authentication'i devre disi birakin. VNC portunu guvenlik "
        "duvari ile sinirlayin."
    ),
    "Apache Tomcat Manager Default Credentials": (
        "Tomcat manager varsayilan kimlik bilgilerini degistirin. Manager "
        "uygulamasini kaldirin veya yalnizca localhost'a sinirlayin. "
        "Yonetim arayuzune MFA/erisim kontrolu uygulayin."
    ),
}

DEFAULT_REMEDIATION = (
    "Ilgili bileseni en son guvenli surume guncelleyin, varsayilan "
    "yapilandirmalari sikilastirin ve en az yetki ilkesini uygulayin. "
    "OWASP guvenlik onerilerini takip edin."
)


def get_remediation(category: str) -> str:
    """Kategori icin gercek remediation onerisi dondurur."""
    return REMEDIATION_MAP.get(category, DEFAULT_REMEDIATION)
