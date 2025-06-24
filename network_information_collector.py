import random
import socket
import requests
import subprocess
import time
import json
import re
import whois

WEBSITES = [
    # Americas (North & South)
    "google.com", "amazon.com", "microsoft.com", "apple.com", "facebook.com",
    "wikipedia.org", "twitter.com", "linkedin.com", "reddit.com", "netflix.com",
    "nytimes.com", "wsj.com", "cnn.com", "espn.com", "weather.com",
    "cbc.ca", "amazon.ca", "canada.ca", # Canada
    "globo.com", "uol.com.br", "mercadolivre.com.br", "gov.br", # Brazil
    "lanacion.com.ar", "mercadolibre.com.ar", "clarin.com", # Argentina
    "eluniversal.com.mx", "televisa.com", "gob.mx", # Mexico
    "co.gov.co", "eltiempo.com", # Colombia
    "cl.gov.cl", "emol.com", # Chile
    "peru.gob.pe", "elcomercio.pe", # Peru

    # Europe
    "bbc.co.uk", "theguardian.com", "gov.uk", "amazon.co.uk", # UK
    "dw.com", "spiegel.de", "bundesregierung.de", "zalando.de", # Germany
    "lemonde.fr", "lefigaro.fr", "gouv.fr", "orange.fr", # France
    "elpais.com", "elmundo.es", "gob.es", "elcorteingles.es", # Spain
    "repubblica.it", "corriere.it", "governo.it", # Italy
    "yandex.ru", "rt.com", "kremlin.ru", # Russia
    "europa.eu", "ec.europa.eu", # European Union
    "nos.nl", "nu.nl", # Netherlands
    "svt.se", "aftonbladet.se", # Sweden
    "dr.dk", "berlingske.dk", # Denmark
    "vg.no", "nrk.no", # Norway
    "finland.fi", "yle.fi", # Finland
    "poland.pl", "onet.pl", # Poland

    # Asia
    "rakuten.co.jp", "yahoo.co.jp", "go.jp", # Japan
    "baidu.com", "qq.com", "sina.com.cn", "gov.cn", # China
    "timesofindia.indiatimes.com", "ndtv.com", "nic.in", # India
    "naver.com", "daum.net", "korea.kr", # South Korea
    "sg.gov.sg", "straitstimes.com", # Singapore
    "id.go.id", "kompas.com", # Indonesia
    "thailand.go.th", "bangkokpost.com", # Thailand
    "gov.pk", "dawn.com", # Pakistan
    "gov.ph", "rappler.com", # Philippines

    # Oceania
    "abc.net.au", "smh.com.au", "gov.au", "seek.com.au", # Australia
    "stuff.co.nz", "nzherald.co.nz", "govt.nz", # New Zealand

    # Africa
    "news24.com", "gov.za", "iol.co.za", # South Africa
    "eg.gov.eg", "ahram.org.eg", # Egypt
    "premiumtimesng.com", "nigeria.gov.ng", # Nigeria
    "kenya.go.ke", "nation.africa", # Kenya
    "algeria.dz", "aps.dz", # Algeria
    "maroc.ma", "lematin.ma", # Morocco
    "senegal.sn", "aps.sn", # Senegal
]

random.shuffle(WEBSITES)

def run_command(command_list):
    try:
        result = subprocess.run(command_list, capture_output=True, text=True, check=True, timeout=30)
        return result.stdout.strip()
    except Exception as e:
        print(f"Comando '{' '.join(command_list)}' falhou, erro: {e}")
        return None
    
def get_dns_info(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception as e:
        print(f"Erro ao obter endereço IP: {e}")
        ip_address = None
    return ip_address

def get_reverse_dns_info(ip_address):
    if not ip_address:
        print("Endereço IP não fornecido para DNS reverso.")
        return None
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        print(f"DNS reverso para {ip_address}: {hostname}")
        return hostname
    except Exception as e:
        print(f"Erro ao obter DNS reverso para {ip_address}: {e}")
        return None
    
def get_ip_geolocation(ip_address):
    if not ip_address:
        print("Endereço IP não fornecido para geolocalização.")
        return None
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=10)
        response.raise_for_status()
        data = response.json()

        if data:
            return {
                "country": data.get("country"),
                "city": data.get("city"),
                "org": data.get("org"),
            }
        else:
            print(f"Geolocalização falhou para {ip_address}")
            return None
    except requests.RequestException as e:
        print(f"Erro ao obter geolocalização para {ip_address}: {e}")
        return None
    finally:
        time.sleep(1.2)

def get_whois_info(domain):
    try:
        data = whois.query(domain)
        whois_data = {
            "domain_name": data.name,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers,
            "status": data.status,
        }
        return whois_data
    except Exception as e:
        print(f"Erro ao obter informações WHOIS para {domain}: {e}")
        return None
    
def get_traceroute_info(ip_address):
    traceroute_hops = []
    cmd = []

    cmd = ["traceroute", "-q", "1", "-m", "30", ip_address]
    output = run_command(cmd)
    print(output)

    if not output:
        print(f"Erro ao executar traceroute para {ip_address}")
        return {}
    
    for line in output.splitlines():
        if "Request timed out" in line or "***" in line or "!" in line:
            continue

        match = re.search(r'^\s*(\d+)\s+.*?\(([\d.]+)\)', line)
        if match:
            try:
                hop_number = int(match.group(1))
                hop_ip = match.group(2)
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hop_ip):
                    traceroute_hops.append({
                        "hop_number": hop_number,
                        "ip_address": hop_ip,
                        "hostname": None,
                        "geolocation": {}
                    })
            except ValueError:
                print(f"Erro ao processar linha de traceroute: {line}")
    return traceroute_hops
    
def collect_network_data(websites_list):
    all_websites_data = []

    for i, website in enumerate(websites_list):
        print(f"Coletando dados para {website} ({i + 1}/{len(websites_list)})")
        site_data = {
            "domain": website,
            "main_ip": None,
            "main_ip_geolocation": {},
            "whois": {},
            "traceroute_hops": [],
        }

        print(f"Obtendo informações DNS para {website}...")
        main_ip = get_dns_info(website)
        site_data["main_ip"] = main_ip

        if not main_ip:
            print(f"Não foi possível obter o IP principal para {website}. Pulando...")
            continue

        #geolocation
        print(f"Obtendo geolocalização para o IP principal {main_ip} de {website}...")
        geolocation = get_ip_geolocation(main_ip)
        site_data["main_ip_geolocation"] = geolocation
        print(f"Geolocalização para {main_ip}: {geolocation}")

        #whois
        print(f"Obtendo informações WHOIS para {website}...")
        whois_info = get_whois_info(website)
        site_data["whois"] = whois_info
        print(f"Informações WHOIS para {website}: {whois_info}")

        #traceroute
        print(f"Obtendo informações de traceroute para {main_ip}...")
        hops = get_traceroute_info(main_ip)
        print(f"Total de saltos no traceroute para {main_ip}: {len(hops)}")


        unique_ips_in_path = {main_ip}
        
        for hop in hops:
            unique_ips_in_path.add(hop["ip_address"])

        ip_details_cache = {}
        for ip in list(unique_ips_in_path):
            geo_info=get_ip_geolocation(ip)
            rev_dns =get_reverse_dns_info(ip)
            ip_details_cache[ip] = {
                "geolocation": geo_info,
                "host_name": rev_dns
            }

       
        final_hops_list = []
        for hop in hops:
            details = ip_details_cache.get(hop["ip_address"], {})
            
            hop["hostname"] = details.get("hostname")
            hop["geolocation"] = details.get("geolocation", {})
            final_hops_list.append(hop) 

        print(f"Informações de traceroute para {main_ip}: {final_hops_list}")
        site_data["traceroute_hops"] = final_hops_list 

        all_websites_data.append(site_data)

        time.sleep(1.2)

    return all_websites_data

if __name__ == "__main__":
    print("Iniciando coleta de dados de rede...")

    collected_data = collect_network_data(WEBSITES)

    try:
        with open("network_data.json", "w", encoding="utf-8") as f:
            json.dump(collected_data, f, indent=4, ensure_ascii=False)
        print("Dados de rede coletados e salvos em 'network_data.json'.")
        print(f"Total de sites processados: {len(collected_data)}")
    except Exception as e:
        print(f"Erro ao salvar dados em 'network_data.json': {e}")