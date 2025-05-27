# REST API com Autenticação Segura e Criptografia

## Descrição

Este projeto implementa uma aplicação cliente-servidor que realiza comunicação segura através de autenticação baseada em tokens JWT assinados digitalmente. O sistema oferece três cenários distintos de autenticação: HMAC (HS256), RSA PKCS#1 v1.5 (RS256) e RSA-PSS (PS256), permitindo análise comparativa de diferentes algoritmos criptográficos.

## Características Principais

- **Comunicação Segura**: Protocolo HTTPS com certificados auto-assinados
- **Autenticação JWT**: Tokens com assinatura digital e tempo de expiração configurável
- **Múltiplos Algoritmos**: Suporte a HMAC, RSA PKCS#1 v1.5 e RSA-PSS
- **Segurança**: Armazenamento seguro de senhas usando hash SHA-256
- **Análise de Vulnerabilidades**: Testes automatizados de ataques conhecidos

## Arquitetura do Sistema

### Componentes

1. **server.py**: Servidor REST com endpoints de autenticação e API protegida
2. **client.py**: Cliente para testes dos cenários de autenticação
3. **security_analysis.py**: Ferramenta de análise de segurança e vulnerabilidades

### Endpoints da API

#### POST /api/auth
Endpoint de autenticação que recebe credenciais e retorna token JWT.

**Parâmetros:**
- `username`: Nome de usuário
- `password`: Senha do usuário
- `scenario`: Cenário de autenticação (1, 2 ou 3)

**Resposta:**
```json
{
  "message": "Autenticação bem-sucedida",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "scenario": "1",
  "algorithm": "HS256"
}
```

#### GET /api/protected
Endpoint protegido que requer token JWT válido.

**Headers:**
- `Authorization`: Bearer {token}
- `X-Auth-Scenario`: Cenário utilizado (1, 2 ou 3)

## Cenários de Implementação

### Cenário 1: HMAC (HS256)
Utiliza chave simétrica para assinatura e verificação de tokens. A mesma chave secreta é compartilhada entre cliente e servidor para validação do token.

**Características:**
- Algoritmo: HMAC-SHA256
- Chave: 256 bits gerada aleatoriamente
- Performance: Alta velocidade de processamento
- Uso recomendado: Aplicações monolíticas

### Cenário 2: RSA PKCS#1 v1.5 (RS256)
Emprega criptografia assimétrica com par de chaves RSA usando padding PKCS#1 v1.5.

**Características:**
- Algoritmo: RSA com SHA-256
- Tamanho da chave: 2048 bits
- Padding: PKCS#1 v1.5
- Uso recomendado: Sistemas distribuídos tradicionais

### Cenário 3: RSA-PSS (PS256)
Utiliza RSA com Probabilistic Signature Scheme, oferecendo maior segurança que PKCS#1 v1.5.

**Características:**
- Algoritmo: RSA-PSS com SHA-256
- Tamanho da chave: 2048 bits
- Padding: PSS (Probabilistic Signature Scheme)
- Uso recomendado: Aplicações que requerem máxima segurança

## Instalação e Execução

### Pré-requisitos

```bash
pip install requests cryptography PyJWT urllib3
```

### Executar o Servidor

```bash
# Servidor HTTPS (recomendado)
python server.py

# Servidor HTTP (apenas para desenvolvimento)
python server.py --no-ssl
```

### Executar o Cliente

```bash
# Testes básicos dos cenários
python client.py

# Demonstração completa de segurança
python client.py --demo
```

### Executar Análise de Segurança

```bash
python security_analysis.py
```

## Análise de Segurança

### Vulnerabilidades Testadas

#### Ataque "None Algorithm"
Teste que verifica se o sistema aceita tokens com algoritmo "none", permitindo bypass da verificação de assinatura.

**Resultado**: O sistema rejeitou adequadamente tokens com algoritmo "none", demonstrando proteção contra este tipo de ataque.

#### Ataque de Confusão de Chaves
Verificação da tentativa de usar chave pública RSA como chave secreta HMAC para forjar tokens.

**Resultado**: A biblioteca PyJWT implementa proteções que impedem o uso de chaves assimétricas como chaves HMAC.

### Comparativo de Performance

#### Geração de Tokens (1000 iterações)
- **HMAC (HS256)**: 0.0274 segundos (0.0274 ms por token)
- **RSA (RS256)**: 1.0599 segundos (1.0599 ms por token)

#### Verificação de Tokens (1000 iterações)
- **HMAC (HS256)**: 0.0375 segundos (0.0375 ms por verificação)
- **RSA (RS256)**: 0.0788 segundos (0.0788 ms por verificação)

**Conclusão**: RSA apresenta sobrecarga significativa, sendo 38.69x mais lento na geração e 2.10x mais lento na verificação comparado ao HMAC.

### Recomendações de Segurança

#### Gerenciamento de Chaves
- Utilizar chaves HMAC de no mínimo 256 bits
- Implementar chaves RSA de no mínimo 2048 bits
- Estabelecer rotação periódica de chaves
- Armazenar chaves de forma segura usando HSM ou KMS

#### Configuração de Tokens
- Definir tempos de expiração adequados ao contexto da aplicação
- Incluir claims essenciais como "iat", "exp", "nbf", "iss" e "aud"
- Implementar identificadores únicos (JTI) para facilitar revogação

#### Validação e Transmissão
- Validar todas as claims relevantes durante verificação
- Especificar explicitamente algoritmos aceitos
- Utilizar exclusivamente HTTPS para transmissão
- Implementar listas de revogação para tokens comprometidos

## Casos de Uso Recomendados

### HMAC (Cenário 1)
Adequado para aplicações monolíticas onde o mesmo sistema gera e valida tokens, priorizando performance sobre distribuição.

### RSA PKCS#1 v1.5 (Cenário 2)
Indicado para sistemas distribuídos tradicionais que necessitam compartilhar capacidade de verificação sem expor chaves privadas.

### RSA-PSS (Cenário 3)
Recomendado para aplicações que exigem máximo nível de segurança criptográfica, especialmente em ambientes regulamentados.

## Arquivos Gerados

Durante a execução, o sistema gera automaticamente:

- `hmac_key.txt`: Chave secreta HMAC para análise
- `rsa_private.pem`: Chave privada RSA
- `rsa_public.pem`: Chave pública RSA
- `server.key`: Chave privada do certificado TLS
- `server.crt`: Certificado TLS auto-assinado

## Considerações de Segurança

Este projeto foi desenvolvido para fins educacionais e demonstra conceitos de segurança criptográfica. Em ambiente de produção, considera-se essencial:

- Utilizar certificados TLS válidos emitidos por autoridades certificadoras reconhecidas
- Implementar mecanismos robustos de gerenciamento de chaves
- Estabelecer políticas adequadas de rotação e revogação de tokens
- Implementar monitoramento e auditoria de tentativas de acesso
- Aplicar princípios de defesa em profundidade

## Análise com Wireshark

Não consegui fazer a análise com o Wireshark, mas é possível capturar os pacotes HTTP/HTTPS trocados entre cliente e servidor para verificar, utilizando as chaves geraddas no arquivo ```server.key```.

---

**Universidade de Brasília – UnB**  
**Departamento de Ciência da Computação**  
**Disciplina: Tópicos Avançados em Segurança Computacional – 2025/1**  
**Professora: Lorena Borges**