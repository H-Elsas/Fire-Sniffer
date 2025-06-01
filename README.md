# 🔥 Fire-Sniffer

Fire-Sniffer é uma ferramenta ⚙️ de **segurança cibernética** que monitora em tempo real o tráfego IP na sua rede local. Ele detecta IPs maliciosos usando a API do [AbuseIPDB](https://www.abuseipdb.com/) e automaticamente bloqueia esses IPs no firewall usando **IPTables**. Além disso, registra logs coloridos 🖍️ no terminal e salva tudo em arquivo para auditoria futura.




## ✨ Funcionalidades

✅ Sniffing de pacotes IP com **Scapy**  
✅ Consulta à API AbuseIPDB com caching inteligente  
✅ Bloqueio automático de IPs maliciosos via **iptables**  
✅ Logging colorido no terminal com **colorlog**  
✅ Log detalhado salvo em arquivo (`history.log`)  
✅ Evita consultas duplicadas e bloqueios repetidos  
✅ Preparado para rodar isolado dentro de **Docker** 🐳




## 🛠️ Tecnologias usadas

- Python 3
- Scapy
- Requests
- IPTables
- Logging + Colorlog
- Docker (opcional, mas recomendado)




## 🚀 Como usar

### 🔧 Pré-requisitos

- Linux com IPTables configurado  
- Python 3.7+ instalado  
- API Key válida no [AbuseIPDB](https://www.abuseipdb.com/)  
- (Opcional) Docker instalado e rodando




### 💻 Instalação manual

```bash
git clone <url-do-repositorio>
cd fire-sniffer
pip install -r requirements.txt
```
---
### 👉 Edite no código a variável ABUSEIPDB_API_KEY com sua chave pessoal.
---



### 👨🏼‍💻 Para rodar localmente 
```bash
sudo python3 main.py
```
### 🐳 Rodando em Docker
```bash
docker build -t fire-sniffer .

sudo docker run --net=host --cap-add=NET_ADMIN --rm fire-sniffer
```




### 📂 Logs
---
- Todos os logs ficam salvos em history.log.
- O terminal exibe mensagens coloridas para facilitar a visualização.
- Logs DEBUG não são mostrados no terminal, apenas INFO e WARNING.




### 📦 Arquivos importantes
---
➛ main.py: script principal do sniffer
➛ requirements.txt: dependências Python
➛ Dockerfile: configuração para rodar dentro de Docker
➛ history.log: arquivo gerado com os logs




### 💡 Próximas melhorias
---

✨ Integração com múltiplas fontes de threat intelligence

✨ Painel web para visualização de IPs e estatísticas

✨ Sistema de desbloqueio automático por tempo ou revisão

✨ Monitoramento bidirecional mais avançado

✨ Configuração externa (ex: arquivo .env)


### 📢 AVISO
---
⚠️ Este projeto é para uso educacional e experimental.

Por favor, tenha cuidado ao rodar scripts que alteram regras do firewall, especialmente em ambientes de produção.

### 🤝 Colabore!

Sinta-se à vontade para abrir PRs, issues ou mandar sugestões!
