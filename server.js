import express from "express";
import crypto from "node:crypto";

// ---------------------------------------------------------------------------
// Config (todas via env — nenhum segredo no repo)
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;

// Segredo da aplicação Trello (API Secret / OAuth1 secret) usado no HMAC-SHA1.
const TRELLO_SECRET = process.env.TRELLO_SECRET || "";

// URL EXATA registrada como callbackURL no Trello. O HMAC concatena o corpo + esta URL,
// então precisa bater byte a byte com o que foi usado na criação do webhook.
const CALLBACK_URL = process.env.CALLBACK_URL || "";

// URL gerada pelo register_hook do Kiro. O adapter faz POST aqui para injetar a tarefa.
// Ex.: https://kiro-crew.bwdi.online/api/hooks/agent
const KIRO_HOOK_URL = process.env.KIRO_HOOK_URL || "";

// Token Bearer do webhook (criado no dashboard: Settings -> Webhooks). Sem ele o endpoint dá 401.
const KIRO_HOOK_TOKEN = process.env.KIRO_HOOK_TOKEN || "";

// Segredo de assinatura do webhook (kc_whs_...). Quando presente, o adapter assina
// cada requisição com HMAC-SHA256 (headers X-KiroCrew-Timestamp/X-KiroCrew-Signature).
const KIRO_SIGNING_SECRET = process.env.KIRO_SIGNING_SECRET || "";

// Origin declarado na chamada ao hook (para passar o CSRF middleware do dashboard).
// Default: a própria origem da KIRO_HOOK_URL. Override via env se necessário.
const KIRO_HOOK_ORIGIN =
  process.env.KIRO_HOOK_ORIGIN ||
  (() => {
    try {
      return new URL(process.env.KIRO_HOOK_URL || "").origin;
    } catch {
      return "";
    }
  })();

// sessionKey e name retornados pelo register_hook (ex.: hook:trello-go-dev-pipeline).
const KIRO_SESSION_KEY = process.env.KIRO_SESSION_KEY || "hook:trello-go-dev-pipeline";
const KIRO_HOOK_NAME = process.env.KIRO_HOOK_NAME || "trello-go-dev-pipeline";

// Agente Kiro que executa a tarefa na sessão de webhook. Precisa ser um agente cujo
// allowedTools já pré-aprove execute_bash/fs_write/Trello writes: a sessão de webhook
// é efêmera e NÃO tem ninguém para confirmar ferramenta, então uma tool que exige
// confirmação trava o turno até o teto de 599s. Vazio = agente default (kirocrew).
const KIRO_HOOK_AGENT = process.env.KIRO_HOOK_AGENT || "";

// Id da lista "Go Dev" — só disparamos quando o card ENTRA nela.
const GO_DEV_LIST_ID = process.env.GO_DEV_LIST_ID || "";

// Id da lista "In Dev" — o adapter move o card pra cá ao acionar o Kiro.
const IN_DEV_LIST_ID = process.env.IN_DEV_LIST_ID || "";

// Id da lista "PR Review" — o Kiro move o card pra cá ao abrir o PR (via prompt).
const PR_REVIEW_LIST_ID = process.env.PR_REVIEW_LIST_ID || "";

// Id da lista "In Deploy" — GATILHO de aprovação: card entrando aqui = "aprovei,
// mergeia e deploya". É o único caminho automático até produção.
const IN_DEPLOY_LIST_ID = process.env.IN_DEPLOY_LIST_ID || "";

// Id da lista "Backlog" — GATILHO de descarte quando o card vem de PR Review:
// fecha o PR (a branch é preservada, para o descarte ser reversível).
const BACKLOG_LIST_ID = process.env.BACKLOG_LIST_ID || "";

// Id da lista "Done" — o Kiro move o card pra cá após o merge (via prompt).
const DONE_LIST_ID = process.env.DONE_LIST_ID || "";

// Id do board da esteira (usado só para log/sanidade).
const BOARD_ID = process.env.BOARD_ID || "";

// Se true, exige HMAC válido. Deixe true em produção.
const VERIFY_HMAC = (process.env.VERIFY_HMAC || "true").toLowerCase() !== "false";

// Mapa opcional etiqueta->repo em JSON. Se o nome da etiqueta já for o nome do repo,
// não precisa configurar. Ex.: {"bull-imoveis":"gonWell/bull-imoveis"}
let LABEL_REPO_MAP = {};
try {
  LABEL_REPO_MAP = JSON.parse(process.env.LABEL_REPO_MAP || "{}");
} catch {
  console.error("[config] LABEL_REPO_MAP não é um JSON válido — ignorando.");
}

// Owner padrão do GitHub quando a etiqueta é só o nome curto do repo.
const DEFAULT_GH_OWNER = process.env.DEFAULT_GH_OWNER || "gonWell";

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express();

// Precisamos do corpo BRUTO para o HMAC (JSON.stringify do Trello != re-serialização nossa).
// Guardamos o raw buffer e também parseamos como JSON.
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf ? buf.toString("utf8") : "";
    },
  })
);

// Health + validação do Trello (ele faz HEAD/GET esperando 200 na criação do webhook).
app.get("/", (_req, res) => res.status(200).json({ status: "ok", service: "trello-kiro-adapter" }));
app.head("/", (_req, res) => res.status(200).end());
app.get("/trello", (_req, res) => res.status(200).send("OK"));
app.head("/trello", (_req, res) => res.status(200).end());

// ---------------------------------------------------------------------------
// Verificação da assinatura do Trello
// Header X-Trello-Webhook = base64( HMAC-SHA1( rawBody + callbackURL, secret ) )
// ---------------------------------------------------------------------------
function verifyTrelloSignature(req) {
  if (!VERIFY_HMAC) return true;
  if (!TRELLO_SECRET || !CALLBACK_URL) {
    console.error("[hmac] TRELLO_SECRET ou CALLBACK_URL ausente — não é possível verificar.");
    return false;
  }
  const headerHash = req.get("x-trello-webhook");
  if (!headerHash) return false;

  const content = (req.rawBody || "") + CALLBACK_URL;
  const expected = crypto.createHmac("sha1", TRELLO_SECRET).update(content).digest("base64");

  // Comparação em tempo constante.
  const a = Buffer.from(headerHash);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Parsing do payload -> tarefa para o Kiro
// ---------------------------------------------------------------------------
function extractMergeMode(desc) {
  if (!desc) return "manual";
  // Procura a linha "MERGE: auto" ou "MERGE: manual" (case-insensitive, ** opcional).
  const m = desc.match(/MERGE:\s*\**\s*(auto|manual)/i);
  return m ? m[1].toLowerCase() : "manual";
}

function resolveRepo(labelNames) {
  for (const label of labelNames) {
    if (!label) continue;
    if (LABEL_REPO_MAP[label]) return LABEL_REPO_MAP[label];
  }
  // Sem mapa: usa a primeira etiqueta como nome curto do repo -> owner/label
  const first = labelNames.find((l) => l && l.trim().length > 0);
  return first ? `${DEFAULT_GH_OWNER}/${first}` : null;
}

function buildKiroPrompt({ repo, mergeMode, cardName, cardDesc, cardUrl, cardId }) {
  return [
    `Nova tarefa da esteira Trello (card movido para "Go Dev").`,
    ``,
    `Repositório alvo: ${repo}`,
    `Modo de merge: ${mergeMode.toUpperCase()}`,
    `Card: ${cardName}`,
    `Link: ${cardUrl}`,
    `Card ID (Trello): ${cardId}`,
    PR_REVIEW_LIST_ID ? `Lista "PR Review" (Trello list id): ${PR_REVIEW_LIST_ID}` : ``,
    ``,
    `--- Descrição do card ---`,
    cardDesc || "(sem descrição)",
    ``,
    `--- Instruções de execução ---`,
    `1. Clone/atualize ${repo} em repos/.`,
    `2. Crie uma branch de feature e implemente a tarefa descrita acima.`,
    `3. Commit + push da branch (por nome de remote) e abra um PR.`,
    mergeMode === "auto"
      ? `4. MERGE=auto: se o build/checks passarem, faça o merge do PR via API REST e deixe o Coolify deployar.`
      : `4. MERGE=manual: PARE após abrir o PR. NÃO faça merge — aguarde revisão humana.`,
    PR_REVIEW_LIST_ID
      ? `5. Ao abrir o PR, mova o card no Trello para "PR Review" usando o Trello MCP: move_card(cardId="${cardId}", listId="${PR_REVIEW_LIST_ID}"). Cole o link do PR como comentário no card.`
      : `5. Ao abrir o PR, mova o card no Trello para a coluna "PR Review" e cole o link do PR como comentário no card.`,
    `6. Responda com o link do PR.`,
  ]
    .filter((l) => l !== ``)
    .join("\n");
}

// Rodada de revisão: já existe PR aberto para este card. NUNCA abrir um segundo PR —
// commits adicionais vão na mesma branch e o PR se atualiza sozinho.
function buildRevisionPrompt({ repo, cardName, cardDesc, cardUrl, cardId, pr, feedback }) {
  const fb = feedback.length
    ? feedback.map((c, i) => `(${i + 1}) ${c.text}`).join("\n\n")
    : "(nenhum comentário novo no card — leia os review comments do PR no GitHub para descobrir o que foi pedido)";
  return [
    `RODADA DE REVISÃO da esteira Trello (card voltou para "Go Dev" com um PR já aberto).`,
    ``,
    `Repositório: ${repo}`,
    `PR JÁ EXISTENTE: ${pr.url} (número ${pr.number})`,
    `Card: ${cardName}`,
    `Link: ${cardUrl}`,
    `Card ID (Trello): ${cardId}`,
    PR_REVIEW_LIST_ID ? `Lista "PR Review" (list id): ${PR_REVIEW_LIST_ID}` : ``,
    ``,
    `--- O que foi pedido nesta rodada ---`,
    fb,
    ``,
    `--- Descrição original do card ---`,
    cardDesc || "(sem descrição)",
    ``,
    `--- Instruções de execução ---`,
    `1. NÃO abra um novo PR e NÃO crie uma branch nova. Descubra a branch do PR ${pr.number} via API REST (GET /repos/${repo}/pulls/${pr.number}, campo head.ref) e faça checkout dela.`,
    `2. Implemente APENAS o que foi pedido nesta rodada. Não refaça o que já estava aprovado.`,
    `3. Commit + push na MESMA branch (por nome de remote). O PR ${pr.number} se atualiza automaticamente.`,
    `4. Comente no card (Card ID ${cardId}) o que mudou nesta revisão, citando o link ${pr.url}.`,
    PR_REVIEW_LIST_ID
      ? `5. Mova o card de volta para "PR Review": move_card(cardId="${cardId}", listId="${PR_REVIEW_LIST_ID}").`
      : `5. Mova o card de volta para a coluna "PR Review".`,
    `6. Responda com o link do PR e o resumo do que mudou.`,
  ]
    .filter((l) => l !== ``)
    .join("\n");
}

// Aprovação: card entrou em "In Deploy". Mergeia o PR — mas só se os checks
// estiverem verdes, porque o merge na branch default dispara deploy em produção.
function buildDeployPrompt({ repo, cardName, cardUrl, cardId, pr }) {
  return [
    `APROVAÇÃO da esteira Trello: o card entrou em "In Deploy", ou seja o Wellington aprovou o PR e quer em produção.`,
    ``,
    `Repositório: ${repo}`,
    `PR a mergear: ${pr.url} (número ${pr.number})`,
    `Card: ${cardName}`,
    `Link: ${cardUrl}`,
    `Card ID (Trello): ${cardId}`,
    PR_REVIEW_LIST_ID ? `Lista "PR Review" (list id): ${PR_REVIEW_LIST_ID}` : ``,
    DONE_LIST_ID ? `Lista "Done" (list id): ${DONE_LIST_ID}` : ``,
    ``,
    `--- Instruções de execução ---`,
    `1. Consulte o PR: GET /repos/${repo}/pulls/${pr.number}. Confirme que está "open" e leia "mergeable"/"mergeable_state".`,
    `2. Confira os checks do commit HEAD do PR: GET /repos/${repo}/commits/<sha>/check-runs e /status. `,
    `3. SE algum check obrigatório estiver falhando, ou houver conflito (mergeable=false): NÃO mergeie. Comente no card explicando exatamente o que está vermelho, mova o card de volta para "PR Review" e pare. Deploy quebrado é pior que deploy atrasado.`,
    `4. SE os checks estiverem verdes (ou não houver nenhum check configurado): mergeie via PUT /repos/${repo}/pulls/${pr.number}/merge (merge_method "squash").`,
    `5. Após o merge, comente no card confirmando o merge + que o Coolify vai deployar automaticamente no push para a branch default.`,
    DONE_LIST_ID
      ? `6. Mova o card para "Done": move_card(cardId="${cardId}", listId="${DONE_LIST_ID}"). O adapter marca o card como concluído automaticamente ao detectar a entrada em Done — você não precisa fazer isso.`
      : `6. Mova o card para a coluna "Done".`,
    `7. Responda dizendo se mergeou ou não, e por quê.`,
  ]
    .filter((l) => l !== ``)
    .join("\n");
}

// Descarte: card voltou de "PR Review" para "Backlog". Fecha o PR SEM apagar a
// branch, para o descarte continuar reversível (reabrir PR / recuperar trabalho).
function buildDiscardPrompt({ repo, cardName, cardUrl, cardId, pr }) {
  return [
    `DESCARTE da esteira Trello: o card voltou de "PR Review" para "Backlog", ou seja o Wellington recusou esta proposta.`,
    ``,
    `Repositório: ${repo}`,
    `PR a fechar: ${pr.url} (número ${pr.number})`,
    `Card: ${cardName}`,
    `Link: ${cardUrl}`,
    `Card ID (Trello): ${cardId}`,
    ``,
    `--- Instruções de execução ---`,
    `1. Feche o PR SEM mergear: PATCH /repos/${repo}/pulls/${pr.number} com {"state":"closed"}.`,
    `2. NÃO apague a branch. O descarte precisa ser reversível — o trabalho fica recuperável e o PR pode ser reaberto.`,
    `3. Comente no card informando que o PR ${pr.number} foi fechado sem merge e que a branch foi preservada (cite o nome dela).`,
    `4. Deixe o card em "Backlog" — não mova para nenhuma outra coluna.`,
    `5. Responda confirmando o fechamento e o nome da branch preservada.`,
  ]
    .filter((l) => l !== ``)
    .join("\n");
}

// Comenta no card. Usado quando o adapter precisa avisar algo sem acionar o agente
// (ex.: card entrou em In Deploy mas não há PR registrado).
async function addCardComment(cardId, text) {
  const key = process.env.TRELLO_KEY;
  const token = process.env.TRELLO_TOKEN;
  if (!key || !token || !cardId || !text) return false;
  try {
    const url = `https://api.trello.com/1/cards/${cardId}/actions/comments?key=${key}&token=${token}`;
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!r.ok) {
      console.error(`[trello] falha ao comentar no card ${cardId}: HTTP ${r.status}`);
      return false;
    }
    return true;
  } catch (e) {
    console.error("[trello] erro ao comentar:", e.message);
    return false;
  }
}

// Marca o card como concluído (o "Concluído" do Trello = campo dueComplete).
// Usado quando o card entra em "Done": o estado visual do board passa a refletir
// que a tarefa terminou, sem depender de o agente lembrar de fazer isso.
async function markCardComplete(cardId) {
  const key = process.env.TRELLO_KEY;
  const token = process.env.TRELLO_TOKEN;
  if (!key || !token || !cardId) return false;
  try {
    const url = `https://api.trello.com/1/cards/${cardId}?dueComplete=true&key=${key}&token=${token}`;
    const r = await fetch(url, { method: "PUT" });
    if (!r.ok) {
      console.error(`[trello] falha ao marcar card ${cardId} como concluído: HTTP ${r.status}`);
      return false;
    }
    return true;
  } catch (e) {
    console.error("[trello] erro ao marcar como concluído:", e.message);
    return false;
  }
}

// Move um card do Trello para outra lista (usado para Go Dev -> In Dev pelo adapter).
async function moveCardToList(cardId, listId) {
  const key = process.env.TRELLO_KEY;
  const token = process.env.TRELLO_TOKEN;
  if (!key || !token || !cardId || !listId) return false;
  try {
    const url = `https://api.trello.com/1/cards/${cardId}?idList=${listId}&key=${key}&token=${token}`;
    const r = await fetch(url, { method: "PUT" });
    if (!r.ok) {
      console.error(`[trello] falha ao mover card ${cardId} -> lista ${listId}: HTTP ${r.status}`);
      return false;
    }
    return true;
  } catch (e) {
    console.error("[trello] erro ao mover card:", e.message);
    return false;
  }
}

// ---------------------------------------------------------------------------
// Comentários do card — é onde vive o estado da esteira e o feedback humano.
// Não guardamos banco de dados: o link do PR que o próprio agente comentou na
// rodada anterior é o que nos diz qual PR pertence a este card.
// ---------------------------------------------------------------------------

// Comentários postados pelo adapter/agente vêm com appCreator preenchido
// (authType appKeyToken). Comentário digitado pelo humano tem appCreator null.
// Esse é o discriminador que separa "nosso registro" de "feedback do Wellington".
async function fetchCardComments(cardId) {
  const key = process.env.TRELLO_KEY;
  const token = process.env.TRELLO_TOKEN;
  if (!key || !token || !cardId) return [];
  try {
    const url = `https://api.trello.com/1/cards/${cardId}/actions?filter=commentCard&limit=50&key=${key}&token=${token}`;
    const r = await fetch(url);
    if (!r.ok) {
      console.error(`[trello] falha ao buscar comentários do card ${cardId}: HTTP ${r.status}`);
      return [];
    }
    const acts = await r.json();
    // A API devolve do mais novo para o mais antigo.
    return (acts || [])
      .map((a) => ({
        text: a?.data?.text || "",
        date: a?.date || "",
        isBot: Boolean(a?.appCreator),
      }))
      .filter((c) => c.text);
  } catch (e) {
    console.error("[trello] erro ao buscar comentários:", e.message);
    return [];
  }
}

const PR_URL_RE = /https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/pull\/(\d+)/;

// Link do PR mais recente que o agente registrou no card (comentários vêm do
// mais novo para o mais antigo, então o primeiro match é o PR atual).
function extractPrUrl(comments) {
  for (const c of comments) {
    const m = c.text.match(PR_URL_RE);
    if (m) return { url: m[0], number: m[1] };
  }
  return null;
}

// Comentários posteriores ao último STATUS do agente = o feedback desta rodada.
//
// A âncora é o comentário de status do agente, identificado por "vem da API E
// contém link de PR" — não por "vem da API" sozinho. Isso importa porque um
// comentário feito por qualquer integração (não só o agente) também chega com
// appCreator preenchido; usar appCreator puro descartaria feedback legítimo
// postado via API. O status do agente sempre carrega o link do PR, então essa
// combinação identifica ele sem ambiguidade.
//
// Devolvido em ordem cronológica.
function newFeedback(comments) {
  const out = [];
  for (const c of comments) {
    if (c.isBot && PR_URL_RE.test(c.text)) break;
    out.push(c);
  }
  return out.reverse();
}


app.post(["/", "/trello"], async (req, res) => {
  // Sempre responder 200 rápido para o Trello não reenfileirar/retry.
  // Validamos e processamos, mas o corpo da resposta não importa para o Trello.
  if (!verifyTrelloSignature(req)) {
    console.warn("[webhook] assinatura inválida — descartando.");
    return res.status(401).json({ error: "invalid signature" });
  }

  const body = req.body || {};
  const action = body.action || {};
  const type = action.type;
  const data = action.data || {};

  // Máquina de estados da esteira: cada MOVIMENTO DE COLUNA é um verbo.
  //   -> Go Dev     = "trabalha" (tarefa nova, ou nova rodada de revisão se já há PR)
  //   -> In Deploy  = "aprovei: mergeia e deploya"  (único caminho até produção)
  //   PR Review -> Backlog = "descarta: fecha o PR"
  // Comentário NÃO é gatilho de propósito: produção só é tocada por um gesto
  // explícito de arrastar o card, nunca por interpretação de texto livre.
  //
  // Os movimentos que o próprio adapter/agente faz (Go Dev->In Dev, In Dev->PR
  // Review, In Deploy->Done) têm listAfter fora do conjunto de gatilhos, então
  // não há risco de loop.
  const listAfterId = data.listAfter?.id;
  const listBeforeId = data.listBefore?.id;

  // Card entrando em "Done": marca como concluído e encerra. Não aciona agente.
  // Vale tanto para o movimento feito pelo agente após o merge quanto para um
  // arrasto manual, então o board nunca fica com card em Done sem estar concluído.
  // Marcar dueComplete não gera listAfter, então isto não pode entrar em loop.
  if (DONE_LIST_ID && type === "updateCard" && listAfterId === DONE_LIST_ID) {
    const doneCardId = data.card?.id;
    const doneCardName = data.card?.name || "(sem nome)";
    const marked = await markCardComplete(doneCardId);
    console.log(`[trello] card "${doneCardName}" -> Done: concluído=${marked ? "ok" : "falhou"}`);
    return res.status(200).json({ completed: marked, card: doneCardName });
  }

  let intent = null;
  if (type === "updateCard" && listAfterId) {
    if (listAfterId === GO_DEV_LIST_ID) {
      intent = "work";
    } else if (IN_DEPLOY_LIST_ID && listAfterId === IN_DEPLOY_LIST_ID) {
      intent = "deploy";
    } else if (
      BACKLOG_LIST_ID &&
      PR_REVIEW_LIST_ID &&
      listAfterId === BACKLOG_LIST_ID &&
      listBeforeId === PR_REVIEW_LIST_ID
    ) {
      intent = "discard";
    }
  }

  if (!intent) {
    return res.status(200).json({ ignored: true, reason: "not a pipeline trigger move" });
  }

  const card = data.card || {};
  const cardId = card.id;
  const cardName = card.name || "(sem nome)";
  const cardShort = card.shortLink;
  const cardUrl = cardShort ? `https://trello.com/c/${cardShort}` : "(sem link)";

  // O payload de updateCard NÃO traz a descrição completa nem as etiquetas.
  // Buscamos o card completo na API do Trello.
  let cardDesc = "";
  let labelNames = [];
  try {
    const key = process.env.TRELLO_KEY;
    const token = process.env.TRELLO_TOKEN;
    if (key && token && cardId) {
      const url = `https://api.trello.com/1/cards/${cardId}?fields=name,desc,labels&key=${key}&token=${token}`;
      const r = await fetch(url);
      if (r.ok) {
        const full = await r.json();
        cardDesc = full.desc || "";
        labelNames = (full.labels || []).map((l) => l.name).filter(Boolean);
      } else {
        console.error(`[trello] falha ao buscar card ${cardId}: HTTP ${r.status}`);
      }
    } else {
      console.error("[trello] TRELLO_KEY/TRELLO_TOKEN ausentes — não dá para enriquecer o card.");
    }
  } catch (e) {
    console.error("[trello] erro ao buscar card:", e.message);
  }

  const repo = resolveRepo(labelNames);
  const mergeMode = extractMergeMode(cardDesc);

  if (!repo) {
    console.warn(`[webhook] card "${cardName}" sem etiqueta de projeto — não sei qual repo. Ignorando.`);
    return res.status(200).json({ ignored: true, reason: "no project label" });
  }

  // O estado da esteira vive nos comentários do card: o link do PR que o agente
  // registrou na rodada anterior identifica o PR deste card, e os comentários
  // humanos posteriores a ele são o feedback desta rodada.
  const comments = await fetchCardComments(cardId);
  const pr = extractPrUrl(comments);

  let prompt;
  let phase;

  if (intent === "work") {
    if (pr) {
      phase = "revision";
      prompt = buildRevisionPrompt({
        repo, cardName, cardDesc, cardUrl, cardId, pr, feedback: newFeedback(comments),
      });
    } else {
      phase = "first-round";
      prompt = buildKiroPrompt({ repo, mergeMode, cardName, cardDesc, cardUrl, cardId });
    }
  } else if (intent === "deploy") {
    if (!pr) {
      // Sem PR não há o que mergear. Não inventamos estado: avisamos no card.
      console.warn(`[webhook] card "${cardName}" entrou em In Deploy sem PR conhecido — ignorando.`);
      await addCardComment(
        cardId,
        "⚠️ Card movido para In Deploy, mas não encontrei nenhum PR registrado nos comentários deste card. Nada foi mergeado. Mova para Go Dev para a esteira trabalhar, ou cole o link do PR num comentário e mova de novo para In Deploy."
      );
      return res.status(200).json({ ignored: true, reason: "no PR to merge" });
    }
    phase = "deploy";
    prompt = buildDeployPrompt({ repo, cardName, cardUrl, cardId, pr });
  } else {
    if (!pr) {
      console.warn(`[webhook] card "${cardName}" descartado sem PR conhecido — nada a fechar.`);
      return res.status(200).json({ ignored: true, reason: "no PR to close" });
    }
    phase = "discard";
    prompt = buildDiscardPrompt({ repo, cardName, cardUrl, cardId, pr });
  }

  if (!KIRO_HOOK_URL) {
    console.error("[kiro] KIRO_HOOK_URL não configurada — não é possível disparar.");
    return res.status(200).json({ ignored: true, reason: "no KIRO_HOOK_URL" });
  }

  try {
    const headers = { "Content-Type": "application/json" };
    if (KIRO_HOOK_TOKEN) headers["Authorization"] = `Bearer ${KIRO_HOOK_TOKEN}`;
    // O endpoint /api/hooks/agent passa pelo CSRF middleware do dashboard, que exige
    // um Origin na allowlist. Chamada server-to-server: declaramos a própria origem
    // do dashboard (derivada de KIRO_HOOK_URL) para satisfazer o check.
    if (KIRO_HOOK_ORIGIN) headers["Origin"] = KIRO_HOOK_ORIGIN;
    const hookBody = JSON.stringify({
      message: prompt,
      sessionKey: KIRO_SESSION_KEY,
      name: KIRO_HOOK_NAME,
      ...(KIRO_HOOK_AGENT ? { agent: KIRO_HOOK_AGENT } : {}),
    });
    // Assinatura HMAC-SHA256 do Kiro: sha256=HMAC(secret, `${timestamp}.${body}`).
    if (KIRO_SIGNING_SECRET) {
      const ts = Math.floor(Date.now() / 1000).toString();
      const sig = crypto
        .createHmac("sha256", KIRO_SIGNING_SECRET)
        .update(ts + "." + hookBody)
        .digest("hex");
      headers["X-KiroCrew-Timestamp"] = ts;
      headers["X-KiroCrew-Signature"] = "sha256=" + sig;
    }
    const r = await fetch(KIRO_HOOK_URL, {
      method: "POST",
      headers,
      body: hookBody,
    });
    console.log(
      `[kiro] disparado para "${cardName}" (fase=${phase}, repo=${repo}, merge=${mergeMode}, pr=${pr ? "#" + pr.number : "-"}, agent=${KIRO_HOOK_AGENT || "default"}) -> HTTP ${r.status}`
    );
    // Só a fase de trabalho move o card para "In Dev". Nas fases de deploy e
    // descarte o card já está na coluna certa (In Deploy / Backlog) e é o agente
    // que o leva para Done, então mexer aqui só criaria estado falso.
    if (r.ok && phase !== "deploy" && phase !== "discard" && IN_DEV_LIST_ID) {
      const moved = await moveCardToList(cardId, IN_DEV_LIST_ID);
      console.log(`[trello] card "${cardName}" -> In Dev: ${moved ? "ok" : "falhou"}`);
    }
  } catch (e) {
    console.error("[kiro] erro ao chamar KIRO_HOOK_URL:", e.message);
    return res.status(200).json({ triggered: false, error: e.message });
  }

  return res.status(200).json({ triggered: true, phase, repo, mergeMode, card: cardName });
});

export {
  extractMergeMode,
  resolveRepo,
  buildKiroPrompt,
  buildRevisionPrompt,
  buildDeployPrompt,
  buildDiscardPrompt,
  extractPrUrl,
  newFeedback,
};

// Não sobe o servidor quando importado por um teste de unidade.
if (process.env.ADAPTER_NO_LISTEN !== "true") {
  app.listen(PORT, () => {
    console.log(`trello-kiro-adapter ouvindo na porta ${PORT}`);
    console.log(`  board=${BOARD_ID || "(não setado)"} goDevList=${GO_DEV_LIST_ID || "(não setado)"}`);
    console.log(`  verifyHmac=${VERIFY_HMAC} hookConfigured=${Boolean(KIRO_HOOK_URL)}`);
  });
}
