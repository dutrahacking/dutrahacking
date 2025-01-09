from flask import Flask, request, jsonify
from bs4 import BeautifulSoup
import requests
import hashlib
import os

app = Flask(__name__)

# Função para gerar hash SHA-256
def generate_sha256_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Função para realizar login
def login(session):
    usuario = 'solic-gabrielly'
    senha_original = '181318'
    senha_hash = generate_sha256_hash(senha_original)
    login_url = 'https://sisregiii.saude.gov.br/'
    login_headers = {
        'Host': 'sisregiii.saude.gov.br',
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
        'sec-ch-ua': '"Chromium";v="124", "Android WebView";v="124", "Not-A.Brand";v="99"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'https://sisregiii.saude.gov.br',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; SM-A022M Build/RP1A.200720.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6328.0 Mobile Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Referer': 'https://sisregiii.saude.gov.br/cgi-bin/index',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cookie': 'TS019395b4=0140e3e4e596aa60819104086782492e91c3ce1b920d77f9712f46ac8250f2cdc66bca7dbc59fe002e45157c7a368c9358ce7ff2e6; SESSION=80d2c6cac9810894da129a04c2bf0644d62aeb07562b3641622d889cc5ee4073; ID=301389'
    }
    login_data = {
        'usuario': usuario,
        'senha': senha_hash,
        'senha_256': senha_hash,
        'etapa': 'ACESSO',
        'logout': ''
    }
    session.post(login_url, headers=login_headers, data=login_data)

# Rota padrão para evitar 404
@app.route('/')
def home():
    return jsonify({"message": "API de Consulta está funcionando! Use /<cpf> para consultas."})

# Rota para consulta por CPF
@app.route('/<cpf>')
def consulta(cpf):
    session = requests.Session()
    login(session)
    cpf_url = 'https://sisregiii.saude.gov.br/cgi-bin/cadweb50?standalone=1'
    cpf_data = {
        'nu_cns': cpf,
        'nome_paciente': '',
        'nome_mae': '',
        'dt_nascimento': '',
        'uf_nasc': '',
        'mun_nasc': '',
        'uf_res': '',
        'mun_res': '',
        'sexo': '',
        'etapa': 'DETALHAR',
        'url': '',
        'standalone': '1'
    }
    response = session.post(cpf_url, data=cpf_data)
    soup = BeautifulSoup(response.text, 'html.parser')
    dados = []
    table = soup.find('table', class_='table_listagem')
    if table:
        rows = table.find_all('tr')
        for row in rows:
            columns = row.find_all('td')
            row_data = []
            for column in columns:
                row_data.append(column.text.strip())
            dados.append(row_data)
    session.close()

    # Transformar a lista de listas em string formatada
    def formatar_dados(dados):
        resultado = ""
        for item in dados:
            if len(item) == 1:
                resultado += f"{item[0]}\n\n"
            elif len(item) == 2:
                resultado += f"{item[0]}: {item[1]}\n"
            elif len(item) > 2:
                resultado += f"{item[0]}:\n"
                for subitem in item[1:]:
                    resultado += f"  - {subitem}\n"
        return resultado.strip()

    resultado_formatado = formatar_dados(dados)
    return jsonify({"resultado": resultado_formatado})

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))  # Obtém a porta do ambiente
    app.run(host='0.0.0.0', port=port, debug=True)  # Usa 0.0.0.0 para permitir conexões externas
