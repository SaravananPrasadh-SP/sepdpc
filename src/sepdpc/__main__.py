import sys
from pathlib import Path

import typer
from adastra.client import SepClient
from dotenv import set_key, load_dotenv
from rich import print
from rich.table import Table
from typing_extensions import Annotated

from sepdpc import repository

help_text = {
    'host': 'The host of your Starburst Enterprise instance, e.g. https://sep.example.com:8443',
    'user': 'The username you are authenticating with',
    'token': 'The token used for authentication, the part after "Basic" and "-" if no authentication (no password)',
    'domain': 'The domain to filter data products, "none" for no domain filter',
    'catalog': 'The catalog to filter data products, "none" for no catalog filter',
    'product': 'The product to filter data products, "none" for no product filter',
    'insecure': 'Allow insecure connections',
    'roles': 'Roles to filter data products, "*" for all roles',
    'includeDrafts': 'Boolean toggle to include draft data products'
}

config_path = Path.home() / '.sepdpc'


def _opt(help, env=None, inputType=str):
    config = {
        'help': help,
        'prompt': env is None
    }
    if env:
        config['envvar'] = env
    option = typer.Option(**config)

    return Annotated[inputType, option]


HostOpt = _opt(help_text['host'], 'SEPDPC_HOST')
UserOpt = _opt(help_text['user'], 'SEPDPC_USER')
TokenOpt = _opt(help_text['token'], 'SEPDPC_TOKEN')
DomainOpt = _opt(help_text['domain'], 'SEPDPC_DOMAIN')
CatalogOpt = _opt(help_text['catalog'], 'SEPDPC_CATALOG')
productOpt = _opt(help_text['product'], 'SEPDPC_PRODUCT')
rolesOpt = _opt(help_text['roles'], 'SEPDPC_ROLES')
secureOpt = _opt(help_text['insecure'], 'SEPDPC_SECURE', bool)
includeDraftsOpt = _opt(help_text['includeDrafts'], 'SEPDPC_INCLUDE_DRAFTS',bool)


app = typer.Typer()


@app.command()
def configure(host: _opt(help_text['host']), user: _opt(help_text['user']), token: _opt(help_text['token']), \
              domain: _opt(help_text['domain']), catalog: _opt(help_text['catalog']), \
              secure: _opt(help_text['insecure']), roles: _opt(help_text['roles']), \
              product: _opt(help_text['product']), includeDrafts: _opt(help_text['includeDrafts'])):
    config_path.touch(mode=0o600, exist_ok=False)
    set_key(dotenv_path=config_path, key_to_set="SEPDPC_HOST", value_to_set=host)
    set_key(dotenv_path=config_path, key_to_set="SEPDPC_USER", value_to_set=user)
    set_key(dotenv_path=config_path, key_to_set="SEPDPC_TOKEN", value_to_set=token)
    set_key(dotenv_path=config_path, key_to_set="SEPDPC_DOMAIN", value_to_set=domain)
    set_key(dotenv_path=config_path, key_to_set="SEPDPC_CATALOG", value_to_set=catalog)
    set_key(dotenv_path=config_path, key_to_set="SEPDPC_PRODUCT", value_to_set=product)
    set_key(dotenv_path=config_path, key_to_set="SEPDPC_INSECURE", value_to_set=secure)
    set_key(dotenv_path=config_path, key_to_set="SEPDPC_ROLES", value_to_set=roles)
    set_key(dotenv_path=config_path, key_to_set="SEPDPC_INCLUDE_DRAFTS", value_to_set=includeDrafts)
    print('Configured sepdpc')


@app.command()
def generate(host: HostOpt, user: UserOpt, token: TokenOpt, path: str, domain: DomainOpt = "none", catalog: CatalogOpt = "none", \
             secure: secureOpt = True, includeDrafts: includeDraftsOpt = False, roles: rolesOpt = "*", product: productOpt = "none"):
    if token != '-': token='Basic '+token    
    client = SepClient(host=host, user=user, token=token, verify=secure, roles=roles)
    repo = repository.from_server(client, domain, catalog, product, includeDrafts)
    repository.persist(repo, path)
    print('Remote repository persisted into:', path)

@app.command()
def validate(path: str):
    repo = repository.from_local(path)
    repository.validate(repo)
    print('Validated repository from:', path)


@app.command()
def diff(host: HostOpt, user: UserOpt, token: TokenOpt, path: str, domain: DomainOpt = "none", catalog: CatalogOpt = "none", \
             secure: secureOpt = True, includeDrafts: includeDraftsOpt = False, roles: rolesOpt = "*", product: productOpt = "none"):
    if token != '-': token='Basic '+token
    client = SepClient(host=host, user=user, token=token, verify=secure, roles=roles)      
    remote_repo = repository.from_server(client, domain, catalog, product, includeDrafts)
    local_repo = repository.from_local(path)
    delta = repository.diff(remote_repo, local_repo)

    table = Table(show_header=False, box=None)
    for deleted_domain in delta.deleted_domains:
        table.add_row('-', 'Domain', deleted_domain.name, deleted_domain.id, style='red')
    for created_domain in delta.created_domains:
        table.add_row('+', 'Domain', created_domain.name, created_domain.id, style='green')
    for updated_domain in delta.updated_domains:
        table.add_row('\u25B3', 'Domain', updated_domain.name, updated_domain.id, style='yellow')

    table.add_row()

    for deleted_product in delta.deleted_products:
        table.add_row('-', 'Product', deleted_product.name, deleted_product.id, style='red')
    for created_product in delta.created_products:
        table.add_row('+', 'Product', created_product.name, created_product.id, style='green')
    for updated_product in delta.updated_products:
        table.add_row('\u25B3', 'Product', updated_product.name, updated_product.id, style='yellow')
    for reassigned_product in delta.reassigned_products:
        table.add_row('\u2192', 'Product', reassigned_product.name, reassigned_product.id, style='blue')

    print(table)


@app.command()
def publish(host: HostOpt, user: UserOpt, token: TokenOpt, path: str, domain: DomainOpt = "none", catalog: CatalogOpt = "none", \
             secure: secureOpt = True, includeDrafts: includeDraftsOpt = False, roles: rolesOpt = "*", product: productOpt = "none"):
    if token != '-': token='Basic '+token
    client = SepClient(host=host, user=user, token=token, verify=secure, roles=roles)  
    local_repo = repository.from_local(path)
    repository.publish(client, domain, catalog, product, includeDrafts, local_repo)
    print('Published repository from:', path)


def main():
    # load dotenv
    load_dotenv(dotenv_path=config_path)
    app()


if __name__ == "__main__":
    sys.exit(main())
