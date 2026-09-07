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
// Endpoint principal do webhook
// ---------------------------------------------------------------------------
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

  // Só nos interessa card entrando na lista Go Dev.
  const listAfterId = data.listAfter?.id;
  const enteredGoDev = type === "updateCard" && listAfterId === GO_DEV_LIST_ID;

  if (!enteredGoDev) {
    return res.status(200).json({ ignored: true, reason: "not a move into Go Dev" });
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

  const prompt = buildKiroPrompt({ repo, mergeMode, cardName, cardDesc, cardUrl, cardId });

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
      `[kiro] disparado para "${cardName}" (repo=${repo}, merge=${mergeMode}, agent=${KIRO_HOOK_AGENT || "default"}) -> HTTP ${r.status}`
    );
    // Só move o card para "In Dev" se o Kiro ACEITOU o disparo (2xx). Assim o card
    // não sai de Go Dev quando a chamada falha (401/403/5xx) — evita estado mentiroso.
    if (r.ok && IN_DEV_LIST_ID) {
      const moved = await moveCardToList(cardId, IN_DEV_LIST_ID);
      console.log(`[trello] card "${cardName}" -> In Dev: ${moved ? "ok" : "falhou"}`);
    }
  } catch (e) {
    console.error("[kiro] erro ao chamar KIRO_HOOK_URL:", e.message);
    return res.status(200).json({ triggered: false, error: e.message });
  }

  return res.status(200).json({ triggered: true, repo, mergeMode, card: cardName });
});

export { extractMergeMode, resolveRepo, buildKiroPrompt };

// Não sobe o servidor quando importado por um teste de unidade.
if (process.env.ADAPTER_NO_LISTEN !== "true") {
  app.listen(PORT, () => {
    console.log(`trello-kiro-adapter ouvindo na porta ${PORT}`);
    console.log(`  board=${BOARD_ID || "(não setado)"} goDevList=${GO_DEV_LIST_ID || "(não setado)"}`);
    console.log(`  verifyHmac=${VERIFY_HMAC} hookConfigured=${Boolean(KIRO_HOOK_URL)}`);
  });
}
