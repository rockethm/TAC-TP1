import jwt
import json
import base64
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def decode_jwt_without_verification(token):
    """Decodifica um token JWT sem verificar a assinatura"""
    parts = token.split('.')
    if len(parts) != 3:
        return "Token JWT inválido"

    # Decodificar o cabeçalho
    header_bytes = base64.urlsafe_b64decode(parts[0] + '=' * (4 - len(parts[0]) % 4))
    header = json.loads(header_bytes.decode('utf-8'))

    # Decodificar o payload
    payload_bytes = base64.urlsafe_b64decode(parts[1] + '=' * (4 - len(parts[1]) % 4))
    payload = json.loads(payload_bytes.decode('utf-8'))

    return {
        "header": header,
        "payload": payload,
        "signature": parts[2]
    }


def demonstrate_none_algorithm_attack(token, secret_key):
    """Demonstra o ataque 'none algorithm' em tokens JWT"""
    # Decodificar o token sem verificação
    decoded = decode_jwt_without_verification(token)

    # Criar um novo payload com role elevado
    payload = decoded["payload"]
    payload["role"] = "admin"  # Elevação de privilégios

    # Codificar o payload em base64
    payload_json = json.dumps(payload).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode().rstrip('=')

    # Criar um header com algoritmo "none"
    header = {"alg": "none", "typ": "JWT"}
    header_json = json.dumps(header).encode()
    header_b64 = base64.urlsafe_b64encode(header_json).decode().rstrip('=')

    # Montar o token falsificado (sem assinatura)
    forged_token = f"{header_b64}.{payload_b64}."

    print("\nAtaque none algorithm")
    print("Token original:", token)
    print("Token falso (usando algoritmo 'none'):", forged_token)

    print("\nTeste 1: Teste com o token falso")
    try:
        decoded_payload = jwt.decode(forged_token, secret_key, algorithms=["HS256"])
        print("Falha - token com algoritmo 'none' foi aceito.")
        print("Payload decodificado:", decoded_payload)
    except Exception as e:
        print("Sucesso - token com algoritmo 'none' foi rejeitado.")
        print("Erro:", str(e))

    print("\nTeste 2: Teste com token falso sem verificação de assinatura")
    try:
        decoded_payload = jwt.decode(forged_token, options={"verify_signature": False})
        print("Ao desativar a verificação de assinatura o token é aceito")
        print("Payload decodificado:", decoded_payload)
    except Exception as e:
        print("Erro ao decodificar mesmo sem verificação:", str(e))


def demonstrate_key_confusion_attack(hmac_token, public_key_pem):
    """Demonstra o ataque de confusão de chaves em tokens JWT"""
    # Decodificar o token HMAC sem verificação
    decoded = decode_jwt_without_verification(hmac_token)

    print("\nAtaque de confusão de chaves")
    print("Token HMAC original:", hmac_token)
    print("\nTentativa de forjar token usando chave pública como HMAC...")

    try:
        # Tentar usar a chave pública como chave HMAC (isso deve falhar em bibliotecas modernas)
        forged_token = jwt.encode(decoded["payload"], public_key_pem, algorithm="HS256")
        print("Falha - token forjado com sucesso:", forged_token)
    except Exception as e:
        print("Sucesso")
        print(f"Erro: {str(e)}")


def analyze_hmac_vs_rsa_performance():
    """Analisa o desempenho dos algoritmos HMAC vs RSA"""
    import time

    print("\nAnálise de desempenho HMAC e RSA")

    # Configuração do teste
    secret_key = "chave_secreta_para_teste" * 4  # Chave de 128 bytes

    # Gerar chave RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Payload de teste
    payload = {
        "sub": "usuario_teste",
        "role": "user",
        "data": "A" * 1000,  # Payload grande para teste
        "exp": int(time.time()) + 3600
    }

    # Teste de desempenho: HMAC
    print("\nTeste de desempenho para HMAC (HS256):")
    start_time = time.time()
    num_iterations = 1000

    for _ in range(num_iterations):
        token = jwt.encode(payload, secret_key, algorithm="HS256")

    hmac_encode_time = time.time() - start_time
    print(f"Tempo médio para gerar {num_iterations} tokens: {hmac_encode_time:.4f} segundos")
    print(f"Tempo médio por token: {(hmac_encode_time / num_iterations) * 1000:.4f} ms")

    # Verificar token HMAC
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    start_time = time.time()

    for _ in range(num_iterations):
        jwt.decode(token, secret_key, algorithms=["HS256"])

    hmac_decode_time = time.time() - start_time
    print(f"Tempo médio para verificar {num_iterations} tokens: {hmac_decode_time:.4f} segundos")
    print(f"Tempo médio por verificação: {(hmac_decode_time / num_iterations) * 1000:.4f} ms")

    # Teste de desempenho: RSA
    print("\nTeste de desempenho para RSA (RS256):")
    start_time = time.time()

    for _ in range(num_iterations):
        token = jwt.encode(payload, private_key, algorithm="RS256")

    rsa_encode_time = time.time() - start_time
    print(f"Tempo médio para gerar {num_iterations} tokens: {rsa_encode_time:.4f} segundos")
    print(f"Tempo médio por token: {(rsa_encode_time / num_iterations) * 1000:.4f} ms")

    # Verificar token RSA
    token = jwt.encode(payload, private_key, algorithm="RS256")
    start_time = time.time()

    for _ in range(num_iterations):
        jwt.decode(token, public_key, algorithms=["RS256"])

    rsa_decode_time = time.time() - start_time
    print(f"Tempo médio para verificar {num_iterations} tokens: {rsa_decode_time:.4f} segundos")
    print(f"Tempo médio por verificação: {(rsa_decode_time / num_iterations) * 1000:.4f} ms")

def security_analysis_main():
    """Função principal para execução das análises de segurança"""
    print("\nAnálises de Segurança")

    # Gerar um token JWT para HMAC (cenário 1)
    secret_key = "chave_secreta_para_teste"
    payload = {
        "sub": "teste",
        "role": "user",
        "exp": int(time.time()) + 300
    }
    hmac_token = jwt.encode(payload, secret_key, algorithm="HS256")

    # Gerar chave RSA para o cenário 2
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Demonstrar ataques e comparar cenários
    demonstrate_none_algorithm_attack(hmac_token, secret_key)
    demonstrate_key_confusion_attack(hmac_token, public_pem)
    analyze_hmac_vs_rsa_performance()


if __name__ == "__main__":
    security_analysis_main()