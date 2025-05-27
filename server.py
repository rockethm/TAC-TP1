import hashlib
import hmac
import json
import jwt
import base64
import time
import secrets
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from urllib.parse import parse_qs, urlparse

# Configurações
SECRET_KEY_HMAC = secrets.token_hex(32)  # Chave secreta para HMAC
JWT_EXPIRATION = 300  # Tempo de expiração do token em segundos (5 minutos)

# Gerar chave RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

# Serializar chaves para armazenamento/transmissão
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Impressão das chaves para análise
print("chaves para análise")

# 1. Chave HMAC
print("\nCHAVE HMAC (HS256):")
print(f"SECRET_KEY_HMAC = '{SECRET_KEY_HMAC}'")
print(f"Tamanho: {len(SECRET_KEY_HMAC)} caracteres ({len(SECRET_KEY_HMAC) * 4} bits)")

# 2. Chave RSA Privada
print("\nCHAVE RSA PRIVADA (RS256/PS256):")
print("Para salvar em arquivo 'rsa_private.pem':")
print(private_pem.decode('utf-8'))

# 3. Chave RSA Pública
print("CHAVE RSA PÚBLICA:")
print("Para salvar em arquivo 'rsa_public.pem':")
print(public_pem.decode('utf-8'))

# 4. Salvar chaves em arquivos
with open('hmac_key.txt', 'w') as f:
    f.write(f"HMAC_SECRET_KEY={SECRET_KEY_HMAC}\n")
    f.write(f"Key_Length={len(SECRET_KEY_HMAC) * 4}_bits\n")

with open('rsa_private.pem', 'wb') as f:
    f.write(private_pem)

with open('rsa_public.pem', 'wb') as f:
    f.write(public_pem)

print("\nArquivos salvos:")
print("- hmac_key.txt (chave HMAC)")
print("- rsa_private.pem (chave RSA privada)")
print("- rsa_public.pem (chave RSA pública)")

print("=" * 60)

# Banco de dados simulado para armazenar usuários
users_db = {
    "admin": {
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "role": "admin"
    },
    "user": {
        "password_hash": hashlib.sha256("user123".encode()).hexdigest(),
        "role": "user"
    }
}


class RequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status_code=200, content_type="application/json"):
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Auth-Scenario')
        self.end_headers()

    def _read_request_body(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        return json.loads(post_data.decode('utf-8'))

    def do_OPTIONS(self):
        self._set_headers()

    def do_GET(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path == "/api/protected":
            auth_header = self.headers.get('Authorization')

            if not auth_header or not auth_header.startswith('Bearer '):
                self._set_headers(401)
                self.wfile.write(json.dumps({"error": "Token não fornecido"}).encode())
                return

            token = auth_header.split(' ')[1]
            scenario = self.headers.get('X-Auth-Scenario', '1')

            # Análise do token recebido
            print(f"\nANÁLISE DE TOKEN RECEBIDO (Cenário {scenario}):")
            print(f"Token: {token}")

            # Decodificar token sem verificação para mostrar conteúdo
            try:
                parts = token.split('.')
                if len(parts) == 3:
                    header_decoded = base64.urlsafe_b64decode(parts[0] + '=' * (4 - len(parts[0]) % 4))
                    payload_decoded = base64.urlsafe_b64decode(parts[1] + '=' * (4 - len(parts[1]) % 4))

                    print(f"Header: {json.loads(header_decoded.decode('utf-8'))}")
                    print(f"Payload: {json.loads(payload_decoded.decode('utf-8'))}")
                    print(f"Signature: {parts[2]}")
            except Exception as e:
                print(f"Erro ao decodificar token: {e}")

            try:
                if scenario == '1':
                    # Cenário 1: HMAC
                    print(f"Verificando com HMAC key: {SECRET_KEY_HMAC}")
                    payload = jwt.decode(token, SECRET_KEY_HMAC, algorithms=["HS256"])
                    algorithm_used = "HS256"
                elif scenario == '2':
                    # Cenário 2: RSA PKCS#1 v1.5
                    print("Verificando com RSA public key (RS256)")
                    payload = jwt.decode(token, public_pem, algorithms=["RS256"])
                    algorithm_used = "RS256"
                elif scenario == '3':
                    # Cenário 3: RSA-PSS
                    print("Verificando com RSA public key (PS256)")
                    payload = jwt.decode(token, public_pem, algorithms=["PS256"])
                    algorithm_used = "PS256"
                else:
                    raise ValueError("Cenário inválido")

                print(f"Token válido. Payload decodificado: {payload}")

                self._set_headers()
                response = {
                    "message": "Acesso autorizado à API protegida",
                    "scenario": scenario,
                    "algorithm": algorithm_used,
                    "data": {
                        "secret_info": "Informação confidencial: XYZ123",
                        "user": payload["sub"],
                        "role": payload["role"],
                        "token_validation": "SUCCESS"
                    }
                }
                self.wfile.write(json.dumps(response).encode())

            except jwt.ExpiredSignatureError:
                print("Token expirado")
                self._set_headers(401)
                self.wfile.write(json.dumps({"error": "Token expirado"}).encode())

            except jwt.InvalidTokenError as e:
                print(f"Token inválido: {e}")
                self._set_headers(401)
                self.wfile.write(json.dumps({"error": "Token inválido"}).encode())

            except Exception as e:
                print(f"Erro geral: {e}")
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode())

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint não encontrado"}).encode())

    def do_POST(self):
        if self.path == "/api/auth":
            try:
                post_data = self._read_request_body()
                username = post_data.get('username')
                password = post_data.get('password')
                scenario = post_data.get('scenario', '1')

                print(f"\nTENTATIVA DE AUTENTICAÇÃO:")
                print(f"Username: {username}")
                print(f"Scenario: {scenario}")

                if username not in users_db:
                    self._set_headers(401)
                    self.wfile.write(json.dumps({"error": "Usuário não encontrado"}).encode())
                    return

                password_hash = hashlib.sha256(password.encode()).hexdigest()
                if password_hash != users_db[username]["password_hash"]:
                    self._set_headers(401)
                    self.wfile.write(json.dumps({"error": "Senha incorreta"}).encode())
                    return

                # Payload com claims de segurança
                current_time = int(time.time())
                payload = {
                    "sub": username,
                    "role": users_db[username]["role"],
                    "iat": current_time,  # Issued at
                    "exp": current_time + JWT_EXPIRATION,  # Expiration
                    "nbf": current_time,  # Not before
                    "iss": "jwt-auth-server",  # Issuer
                    "aud": "jwt-auth-client"  # Audience
                }

                if scenario == '1':
                    # Cenário 1: HMAC
                    token = jwt.encode(payload, SECRET_KEY_HMAC, algorithm="HS256")
                    algorithm = "HS256"
                    print(f"Token gerado com HMAC: {SECRET_KEY_HMAC}")
                elif scenario == '2':
                    # Cenário 2: RSA PKCS#1 v1.5
                    token = jwt.encode(payload, private_key, algorithm="RS256")
                    algorithm = "RS256"
                    print("Token gerado com RSA private key")
                elif scenario == '3':
                    # Cenário 3: RSA-PSS
                    token = jwt.encode(payload, private_key, algorithm="PS256")
                    algorithm = "PS256"
                    print("Token gerado com RSA-PSS private key")
                else:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Cenário inválido"}).encode())
                    return

                print(f"Token gerado: {token}")

                self._set_headers()
                response = {
                    "message": "Autenticação bem-sucedida",
                    "token": token,
                    "expires_in": JWT_EXPIRATION,
                    "scenario": scenario,
                    "algorithm": algorithm,
                    "key_info": {
                        "hmac_key": SECRET_KEY_HMAC if scenario == '1' else None,
                        "rsa_key_size": "2048 bits" if scenario in ['2', '3'] else None
                    }
                }
                self.wfile.write(json.dumps(response).encode())

            except Exception as e:
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode())

        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint não encontrado"}).encode())


def create_self_signed_cert():
    """Cria um certificado auto-assinado para HTTPS"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime

    # Gerar chave privada para o certificado TLS (diferente da chave RSA dos JWTs)
    cert_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Criar certificado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "DF"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Brasília"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UnB"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        cert_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
        ]),
        critical=False,
    ).sign(cert_key, hashes.SHA256(), default_backend())

    # Salvar arquivos TLS
    with open("server.key", "wb") as f:
        f.write(cert_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("server.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("\nCertificado TLS gerado:")
    print("- server.key (chave privada TLS)")
    print("- server.crt (certificado TLS)")


def run_server(port=8000, use_https=True):
    server_address = ('', port)
    httpd = HTTPServer(server_address, RequestHandler)

    if use_https:
        # Criar certificado se não existir
        try:
            with open("server.crt", "rb"):
                pass
        except FileNotFoundError:
            print("Criando certificado auto-assinado...")
            create_self_signed_cert()

        # Configurar SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('server.crt', 'server.key')
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        protocol = "HTTPS"
    else:
        protocol = "HTTP"

    print(f"\nIniciando servidor {protocol} na porta {port}...")
    print(f"Acesse: {'https' if use_https else 'http'}://localhost:{port}")
    print("\nChaves expostas apenas para fins educacionais.")
    print("Use as chaves acima para análise no Wireshark.")
    httpd.serve_forever()


if __name__ == "__main__":
    import sys

    use_https = '--no-ssl' not in sys.argv
    run_server(use_https=use_https)