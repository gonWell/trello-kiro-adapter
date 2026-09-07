# trello-kiro-adapter

Microserviço que conecta a esteira do Trello ao Kiro. Quando um card entra na lista
**Go Dev**, o Trello dispara um webhook para este adapter, que:

1. valida a assinatura HMAC-SHA1 do Trello (`X-Trello-Webhook`);
2. confirma que o card entrou na lista **Go Dev** (`listAfter.id === GO_DEV_LIST_ID`);
3. busca o card completo na API do Trello (descrição + etiquetas);
4. resolve o **repositório** pela etiqueta e o **modo de merge** (`MERGE: auto|manual`) pela descrição;
5. faz `POST` na `KIRO_HOOK_URL` (gerada pelo `register_hook` do Kiro) com a tarefa montada.

## Fluxo

```
Trello (card -> Go Dev) --webhook--> adapter --POST--> KIRO_HOOK_URL --> sessão Kiro
                                                                          |
                                    clona repo, edita, commita, abre PR <-+
                                    (merge automático se MERGE=auto)
```

## Variáveis de ambiente

Veja `.env.example`. Resumo:

| Var | Descrição |
|-----|-----------|
| `TRELLO_SECRET` | API Secret da app Trello (HMAC). |
| `TRELLO_KEY` / `TRELLO_TOKEN` | Credenciais para buscar o card completo. |
| `CALLBACK_URL` | URL exata registrada no Trello (entra no HMAC). |
| `KIRO_HOOK_URL` | URL do `register_hook` do Kiro. **Rotacionável** (veja abaixo). |
| `BOARD_ID` / `GO_DEV_LIST_ID` | IDs do board e da lista Go Dev. |
| `LABEL_REPO_MAP` | JSON opcional etiqueta->`owner/repo`. |
| `DEFAULT_GH_OWNER` | Owner usado quando a etiqueta é só o nome curto do repo. |
| `VERIFY_HMAC` | `true` em produção. |

## Deploy no Coolify (bwdi)

1. App do tipo **Public Repository** apontando para `gonWell/trello-kiro-adapter`, branch `main`, build pack **Dockerfile**.
2. Setar as env vars acima.
3. Expor o domínio `trello-adapter.bwdi.online` (HTTPS — o Trello exige porta 443).
4. Confirmar `GET /trello` -> `200 OK`.

## Registrar o webhook no Trello

```bash
curl -X POST "https://api.trello.com/1/tokens/${TRELLO_TOKEN}/webhooks/?key=${TRELLO_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Esteira Go Dev -> Kiro",
    "callbackURL": "https://trello-adapter.bwdi.online/trello",
    "idModel": "6a9ec8f34ccc85be73a06467"
  }'
```

O `idModel` é o **board** (recebe eventos de todos os cards). O adapter filtra internamente
por `GO_DEV_LIST_ID`, então mover para qualquer outra coluna é ignorado.

## Rotacionar a KIRO_HOOK_URL

A `KIRO_HOOK_URL` vem do `register_hook` e está atrelada a uma sessão do Kiro. Se a sessão
expirar, o disparo para de funcionar. Para rotacionar:

1. Peça ao Kiro (numa sessão) para gerar uma nova hook URL (`register_hook`).
2. Atualize a env `KIRO_HOOK_URL` no app do Coolify.
3. Redeploy (ou hot-reload de env, conforme o Coolify).

O webhook do Trello **não** precisa ser recriado — só a env muda.

## Adicionar novos repos

- Se a etiqueta do card já tem o mesmo nome do repo: nada a fazer (usa `DEFAULT_GH_OWNER/<etiqueta>`).
- Caso contrário: adicione ao `LABEL_REPO_MAP`, ex.:
  ```json
  {"gestao-mobile": "gonWell/gestao-mobile", "nr1": "DanielLima23/nr1"}
  ```

## Segurança

- HMAC obrigatório (`VERIFY_HMAC=true`). Requests sem assinatura válida recebem 401.
- Nenhum segredo no repo — tudo por env no Coolify.
- Trello só chama de `104.192.142.240/28` via 443 (pode-se adicionar filtro de IP se desejado).
