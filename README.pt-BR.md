# cdk-serverless-idp

[Read in English](README.md)

Um **provedor de identidade OpenID Connect multiempresa** para o seu SaaS, num construct do AWS CDK. Roda em Lambda +
DynamoDB e **não custa nada enquanto ninguém está entrando**: não tem servidor ligado, não tem NAT e não tem banco de
dados de instância. Foi pensado para quem está criando o próprio SaaS e quer um caminho seguro para seguir.

- **Realm por cliente.** Cada cliente (escola, clínica, empresa…) tem:
  - as próprias pessoas;
  - as próprias regras de senha e de segundo fator;
  - o próprio login social;
  - a própria marca.
- **Aplicação por SaaS.** Todos os seus produtos entram pelo mesmo provedor. Quem entrou em um entra nos outros do
  mesmo realm, sem digitar a senha de novo.
- **Gancho de post-login.** Depois da autenticação, o provedor pergunta à aplicação se a pessoa pode entrar e o que
  vai no token. O provedor não conhece o seu negócio: papéis, planos e permissões ficam na aplicação.
- **Padrão, não criptografia caseira.** É construído sobre o
  [`oidc-provider`](https://github.com/panva/node-oidc-provider), certificado pela OpenID Foundation:
  - PKCE obrigatório;
  - rotação do token de renovação com detecção de reuso;
  - chaves ES256 com rotação;
  - revogação e logout padrão.

## Começando

```bash
npm install cdk-serverless-idp
```

```ts
const idp = new ServerlessIdp(stack, 'Idp', { domainName: 'id.exemplo.com.br', certificate, mailFrom: 'Exemplo <nao-responda@exemplo.com.br>' });
idp.grantAdmin(backend); // o backend da sua aplicação gerencia realms, aplicações e pessoas
```

Depois do `cdk deploy`, aponte o domínio (CNAME) para a saída `DistributionDomainName` e use a API de
administração para criar um realm, uma aplicação e uma pessoa. Os exemplos estão no [README em inglês](README.md#quick-start).

## Custo

Você paga por uso, não por tempo:
- Lambda;
- DynamoDB sob demanda;
- CloudFront;
- dois segredos no Secrets Manager (cerca de US$ 0,80 por mês);
- e-mails do SES.

Sem ninguém entrando, a conta fica só nos segredos.

## Segurança

O modelo de ameaças e como relatar uma vulnerabilidade estão no [SECURITY.md](SECURITY.md).

## Licença

[Apache-2.0](LICENSE)
