from scapy.all import sniff, IP
from colorlog import ColoredFormatter
import requests
import time
import subprocess
import logging

ABUSEIPDB_API_KEY = "c71e4a93ade656d24ea03086f21899eec6d67c0ef55e355fa23ada88a48c635396ac3e19b788c6df"
API_COOLDOWN = 10  # segundos entre consultas para o mesmo IP

ip_cache = {}  # cache dos IPs consultados: ip -> (timestamp, suspeito)


# Configurando Logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
#logging.basicConfig(filename='history.log', filemode='w', encoding='utf-8')
file_handler = logging.FileHandler('history.log')
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')


color_formatter = ColoredFormatter(
    "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
    log_colors={
        'DEBUG':    'cyan',
        'INFO':     'green',
        'WARNING':  'red',
    }
)
handler.setFormatter(color_formatter)
logger.addHandler(handler)

def check_ip_abuse(ip):
    if ip in ip_cache:
        last_check, suspeito = ip_cache[ip]
        if time.time() - last_check < API_COOLDOWN:
            return suspeito  # retorna resultado cacheado

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            score = data["data"]["abuseConfidenceScore"]
            suspeito = score > 50
            ip_cache[ip] = (time.time(), suspeito)
            return suspeito
        else:
            print(f"Erro AbuseIPDB API: {response.status_code}")
            return False
    except Exception as e:
        print(f"Erro na requisição AbuseIPDB: {e}")
        return False

def process_packet(packet):
    if IP in packet:
        ip_dst = packet[IP].dst
        if check_ip_abuse(ip_dst):
            #print(f"[ALERTA] IP suspeito detectado: {ip_dst}")
            logger.warning(f"IP suspeito detectado: {ip_dst}")
            result_inp = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip_dst, '-j', 'DROP'])
            result_out = subprocess.run(['iptables', '-C', 'OUTPUT', '-d', ip_dst, '-j', 'DROP'])
            if result_inp.returncode != 0 and result_out.returncode != 0: 
                #print(f"[AVISO] Realizando bloqueio na IPTABLES")
                logger.info(f"Realizando bloqueio na IPTABLES")
                subprocess.Popen(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_dst, '-j', 'DROP'])
                subprocess.Popen(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip_dst, '-j', 'DROP'])
            else:
                #print("[AVISO] IP já bloqueado")
                logger.info("IP já bloqueado")
        else:
            logger.info(f"IP {ip_dst} não é malicioso, pulando...")
print("Iniciando sniffing... CTRL+C para parar")
sniff(filter="ip", prn=process_packet, store=0)