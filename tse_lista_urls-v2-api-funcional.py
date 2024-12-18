import requests
import json
import getpass
import urllib3

# Desabilitar aviso de certificado SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Função para autenticar no BIG-IP e obter o token de autenticação
def authenticate_bigip(base_url, username, password):
    url_auth = f'{base_url}/mgmt/shared/authn/login'
    payload = {
        'username': username,
        'password': password,
        'loginProviderName': 'tmos'
    }
    try:
        response = requests.post(url_auth, json=payload, verify=False)
        response.raise_for_status()
        token = response.json()['token']['token']
        return token
    except Exception as e:
        print(f'Erro ao autenticar no BIG-IP: {e}')
        return None

# Função para listar todas as políticas ASM no BIG-IP
def list_asm_policies(base_url, token):
    url_policies = f'{base_url}/mgmt/tm/asm/policies'
    headers = {'X-F5-Auth-Token': token, 'Content-Type': 'application/json'}
    try:
        response = requests.get(url_policies, headers=headers, verify=False)
        response.raise_for_status()
        policies = response.json().get('items', [])
        return policies
    except Exception as e:
        print(f'Erro ao obter políticas ASM: {e}')
        return []

# Função para listar as URLs de uma política ASM
def list_policy_urls(base_url, token, policy_id):
    url_urls = f'{base_url}/mgmt/tm/asm/policies/{policy_id}/urls'
    headers = {'X-F5-Auth-Token': token, 'Content-Type': 'application/json'}
    try:
        response = requests.get(url_urls, headers=headers, verify=False)
        response.raise_for_status()
        urls = response.json().get('items', [])
        return [url for url in urls if not url.get('name', '').startswith('*')]
    except Exception as e:
        print(f'Erro ao obter URLs da política {policy_id}: {e}')
        return []

# Função para criar iRule para uma política
def create_irule(policy_name, urls):
    profile_name = f"profile_stats_{policy_name.replace(' ', '_')}"
    irule_name = f"irule_stats_{policy_name.replace(' ', '_')}"
    irule_content = "when HTTP_REQUEST {\n"
    for url in urls:
        url_name = url.get('name', '/')
        formatted_url_name = url_name.replace('/', '')
        irule_content += f"    if {{ [HTTP::path] starts_with \"{url_name}\" }} {{\n"
        irule_content += f"        STATS::incr {profile_name} {formatted_url_name}\n"
        irule_content += "    }\n"
    irule_content += "}"
    save_irule_to_file(irule_name, irule_content)
    return irule_name, irule_content, profile_name, [url.get('name', '/').replace('/', '') for url in urls]

# Função para salvar o conteúdo da iRule em um arquivo
def save_irule_to_file(irule_name, irule_content):
    filename = f"{irule_name}.tcl"
    with open(filename, 'w') as file:
        file.write(irule_content)
    print(f'iRule salva em: {filename}')

# Função para criar o profile statistics via API
def create_statistics_profile_api(base_url, token, profile_name, fields):
    url_profile = f'{base_url}/mgmt/tm/ltm/profile/statistics'
    headers = {'X-F5-Auth-Token': token, 'Content-Type': 'application/json'}
    profile_content = {
        "name": profile_name,
        "partition": "Common",
        "defaultsFrom": "/Common/stats"
    }
    for index, field in enumerate(fields, start=1):
        profile_content[f"field{index}"] = field
    save_profile_to_file(profile_name, profile_content)
    try:
        response = requests.post(url_profile, headers=headers, json=profile_content, verify=False)
        response.raise_for_status()
        print(f'Profile statistics criado via API: {profile_name}')
    except Exception as e:
        print(f'Erro ao criar o profile statistics via API: {e}')

# Função para salvar o conteúdo do profile de estatísticas em um arquivo
def save_profile_to_file(profile_name, profile_content):
    filename = f"{profile_name}.conf"
    with open(filename, 'w') as file:
        file.write(json.dumps(profile_content, indent=4))
    print(f'Profile statistics salvo em: {filename}')

# Função para criar a iRule via API
def create_irule_api(base_url, token, irule_name, irule_content):
    url_irule = f'{base_url}/mgmt/tm/ltm/rule'
    headers = {'X-F5-Auth-Token': token, 'Content-Type': 'application/json'}
    irule_data = {
        "name": irule_name,
        "apiAnonymous": irule_content
    }
    try:
        response = requests.post(url_irule, headers=headers, json=irule_data, verify=False)
        response.raise_for_status()
        print(f'iRule criada via API: {irule_name}')
    except Exception as e:
        print(f'Erro ao criar a iRule via API: {e}')

# Função principal
def main():
    base_url = input('Insira a URL base do BIG-IP (exemplo: https://bigip.example.com): ')
    username = input('Insira seu nome de usuário: ')
    password = getpass.getpass('Insira sua senha: ')

    token = authenticate_bigip(base_url, username, password)
    if not token:
        print('Falha na autenticação. Saindo...')
        return

    policies = list_asm_policies(base_url, token)
    if not policies:
        print('Nenhuma política ASM encontrada. Saindo...')
        return

    create_api_resources = input('Deseja criar as iRules e os Profiles de Estatísticas via API? (s/n): ').strip().lower() == 's'

    for policy in policies:
        policy_name = policy.get('name', 'N/A')
        policy_id = policy.get('id', 'N/A')
        urls = list_policy_urls(base_url, token, policy_id)
        if urls:
            irule_name, irule_content, profile_name, fields = create_irule(policy_name, urls)
            if create_api_resources:
                create_statistics_profile_api(base_url, token, profile_name, fields)
                create_irule_api(base_url, token, irule_name, irule_content)

if __name__ == "__main__":
    main()
