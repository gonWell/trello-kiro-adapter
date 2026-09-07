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
const KIRO_HOOK_URL = process.env.KIRO_HOOK_URL || "";

// Id da lista "Go Dev" — só disparamos quando o card ENTRA nela.
const GO_DEV_LIST_ID = process.env.GO_DEV_LIST_ID || "";

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

function buildKiroPrompt({ repo, mergeMode, cardName, cardDesc, cardUrl }) {
  return [
    `Nova tarefa da esteira Trello (card movido para "Go Dev").`,
    ``,
    `Repositório alvo: ${repo}`,
    `Modo de merge: ${mergeMode.toUpperCase()}`,
    `Card: ${cardName}`,
    `Link: ${cardUrl}`,
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
    `5. Responda com o link do PR.`,
  ].join("\n");
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
      const url = `https://api.trello.com/1/cards/${cardId}?fields=name,desc&labels=all&key=${key}&token=${token}`;
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

  const prompt = buildKiroPrompt({ repo, mergeMode, cardName, cardDesc, cardUrl });

  if (!KIRO_HOOK_URL) {
    console.error("[kiro] KIRO_HOOK_URL não configurada — não é possível disparar.");
    return res.status(200).json({ ignored: true, reason: "no KIRO_HOOK_URL" });
  }

  try {
    const r = await fetch(KIRO_HOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: prompt,
        source: "trello-kiro-adapter",
        card: { id: cardId, name: cardName, url: cardUrl, repo, mergeMode },
      }),
    });
    console.log(
      `[kiro] disparado para "${cardName}" (repo=${repo}, merge=${mergeMode}) -> HTTP ${r.status}`
    );
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
