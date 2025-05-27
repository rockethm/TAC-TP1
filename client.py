import requests
import json
import time
import sys
import urllib3

# Desabilitar avisos de SSL para certificados self-signed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuração
SERVER_URL = "https://localhost:8000"  # Agora usando HTTPS
AUTH_ENDPOINT = f"{SERVER_URL}/api/auth"
PROTECTED_ENDPOINT = f"{SERVER_URL}/api/protected"


def authenticate(username, password, scenario='1'):
    """Autentica o usuário e retorna o token JWT"""
    auth_payload = {
        "username": username,
        "password": password,
        "scenario": scenario
    }

    try:
        response = requests.post(
            AUTH_ENDPOINT,
            json=auth_payload,
            verify=False,  # Para certificados self-signed
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            algorithm = data.get("algorithm", "Unknown")
            print(f"Autenticação bem-sucedida para o cenário {scenario} (Algoritmo: {algorithm})!")
            return data["token"]
        else:
            print("Falha na autenticação:", response.json().get("error", "Erro desconhecido"))
            return None
    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão: {e}")
        return None


def access_protected_api(token, scenario='1'):
    """Acessa a API protegida usando o token JWT"""
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Auth-Scenario": scenario
    }

    try:
        response = requests.get(
            PROTECTED_ENDPOINT,
            headers=headers,
            verify=False,  # Para certificados self-signed
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            print("Sucesso - acesso à API protegida")
            print(f"Algoritmo usado: {data.get('algorithm', 'Unknown')}")
            print("Dados recebidos:", json.dumps(data, indent=2))
            return True
        else:
            print("Falha no acesso à API protegida:", response.json().get("error", "Erro desconhecido"))
            return False
    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão: {e}")
        return False


def test_invalid_token(scenario='1'):
    """Testa o acesso com um token inválido"""
    # Token JWT inválido (payload alterado manualmente)
    invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZXIiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.invalidSignature"

    print("\nTestando token inválido")
    access_protected_api(invalid_token, scenario)


def test_expired_token(token, scenario='1'):
    """Espera o token expirar e tenta acessar a API protegida"""
    time.sleep(5)

    print("Tentando acessar a API protegida com token expirado")
    access_protected_api(token, scenario)


def test_algorithm_confusion_attack():
    """Testa ataques de confusão de algoritmo"""
    print("\ntestes de ataques")

    # Obter token HMAC
    token_hmac = authenticate("admin", "admin123", "1")
    if not token_hmac:
        return

    # Tentar usar token HMAC no cenário RSA
    print("\nTentando usar token HMAC no cenário RSA")
    headers = {
        "Authorization": f"Bearer {token_hmac}",
        "X-Auth-Scenario": "2"  # Forçar cenário RSA
    }

    try:
        response = requests.get(
            PROTECTED_ENDPOINT,
            headers=headers,
            verify=False,
            timeout=10
        )

        if response.status_code == 200:
            print("falha: token HMAC foi aceito no cenário RSA")
        else:
            print("Sucesso: Token HMAC foi rejeitado no cenário RSA")
            print("Erro:", response.json().get("error"))
    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão: {e}")


def run_scenario(scenario):
    """Executa um cenário de teste completo"""
    scenario_names = {
        '1': 'HMAC (HS256)',
        '2': 'RSA PKCS#1 v1.5 (RS256)',
        '3': 'RSA-PSS (PS256)'
    }

    print(f"\nCenário{scenario}: {scenario_names.get(scenario, 'Unknown')}")

    # Autenticação
    token = authenticate("admin", "admin123", scenario)

    if not token:
        print(f"Não foi possível prosseguir com o cenário {scenario}.")
        return

    # Acessar API protegida com token válido
    print("\nAcessando API protegida com token válido...")
    success = access_protected_api(token, scenario)

    if not success:
        print(f"Falha no teste do cenário {scenario}.")
        return

    # Testar token inválido
    test_invalid_token(scenario)

    # Teste opcional: esperar o token expirar (descomente para testar)
    # test_expired_token(token, scenario)

    return token


def security_demonstration():
    """Demonstra aspectos de segurança"""
    print("\nDemontsração")

    # Teste de diferentes cenários
    tokens = {}
    for scenario in ['1', '2', '3']:
        token = run_scenario(scenario)
        if token:
            tokens[scenario] = token

    # Teste de confusão de algoritmos
    test_algorithm_confusion_attack()

    # Análise de tokens
    print("\nAnálise de tokens")
    for scenario, token in tokens.items():
        print(f"\nCenário {scenario} - Token (primeiros 50 chars): {token[:50]}...")


def main():
    print("Cliente seguro JWT")
    print("Testando comunicação HTTPS com autenticação JWT")

    if len(sys.argv) > 1 and sys.argv[1] == '--demo':
        security_demonstration()
    else:
        # Executar cenários básicos
        run_scenario('1')  # HMAC
        run_scenario('2')  # RSA PKCS#1 v1.5
        run_scenario('3')  # RSA-PSS


if __name__ == "__main__":
    main()