FROM python:3.11-slim

# Directory
WORKDIR /app

# Copia os arquivos pra imagem que vai rodar
COPY . /app

# Instalando dependências
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y libpcap-dev

# Executar container
CMD ["python", "main.py"]