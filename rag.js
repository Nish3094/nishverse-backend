// ── RAG Module ─────────────────────────────────────────────────────────────
// Scrapes CIS AWS Foundations Benchmark controls from public sources,
// chunks them, embeds via HuggingFace, and stores in Pinecone.
//
// No CIS knowledge is hardcoded here. Add new sources to CIS_SOURCES and
// call /rag/sync — zero code changes needed for new CIS standards.

const PINECONE_BASE_URL = process.env.PINECONE_INDEX_HOST;

// ── CIS public sources ─────────────────────────────────────────────────────
// Steampipe's open-source CIS v3.0 markdown docs — one file per control.
// To add a new CIS standard: add its URL + service here, then hit /rag/sync.
const CIS_SOURCES = [
  // IAM
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_1_4.md",  service: "IAM", section: "Identity and Access Management" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_1_5.md",  service: "IAM", section: "Identity and Access Management" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_1_6.md",  service: "IAM", section: "Identity and Access Management" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_1_8.md",  service: "IAM", section: "Identity and Access Management" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_1_9.md",  service: "IAM", section: "Identity and Access Management" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_1_10.md", service: "IAM", section: "Identity and Access Management" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_1_14.md", service: "IAM", section: "Identity and Access Management" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_1_16.md", service: "IAM", section: "Identity and Access Management" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_1_17.md", service: "IAM", section: "Identity and Access Management" },
  // S3
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_2_1_1.md", service: "S3", section: "Storage" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_2_1_2.md", service: "S3", section: "Storage" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_2_1_4.md", service: "S3", section: "Storage" },
  // EC2 / EBS
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_2_2_1.md", service: "EC2", section: "Compute" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_5_2.md",   service: "EC2", section: "Networking" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_5_3.md",   service: "EC2", section: "Networking" },
  // RDS
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_2_3_2.md", service: "RDS", section: "Database" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_2_3_3.md", service: "RDS", section: "Database" },
  // CloudTrail
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_3_1.md",   service: "CloudTrail", section: "Logging" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_3_2.md",   service: "CloudTrail", section: "Logging" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_3_3.md",   service: "CloudTrail", section: "Logging" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_3_7.md",   service: "CloudTrail", section: "Logging" },
  // VPC / Networking
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_3_9.md",   service: "VPC", section: "Networking" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_4_1.md",   service: "CloudWatch", section: "Monitoring" },
  { url: "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/main/cis_v300/docs/cis_v300_4_3.md",   service: "CloudWatch", section: "Monitoring" },
];

// ── Scrape one CIS markdown file ───────────────────────────────────────────
async function scrapeSource(source) {
  try {
    const res = await fetch(source.url, {
      headers: { "User-Agent": "nishverse-scanner/1.0" },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) { console.warn(`[RAG] ${res.status} fetching ${source.url}`); return null; }
    const text = await res.text();
    if (!text || text.length < 50) { console.warn(`[RAG] Empty: ${source.url}`); return null; }

    // Derive control ID from filename: cis_v300_2_1_4.md → CIS 2.1.4
    const match = source.url.match(/cis_v\d+_(\d+(?:_\d+)*)\.md$/);
    const controlNum = match ? match[1].replace(/_/g, ".") : "unknown";
    const titleMatch = text.match(/^#+\s+(.+)/m);
    const title = titleMatch ? titleMatch[1].replace(/`/g, "").trim() : `CIS ${controlNum}`;

    return {
      id:      `cis-${controlNum.replace(/\./g, "-")}`,
      control: `CIS ${controlNum}`,
      title,
      service: source.service,
      section: source.section,
      text:    text.slice(0, 3000),
      source:  source.url,
    };
  } catch (e) {
    console.warn(`[RAG] Scrape error ${source.url}:`, e.message);
    return null;
  }
}

// ── Embedding via HuggingFace ───────────────────────────────────────────────
async function embed(text) {
  if (!process.env.HF_API_KEY) throw new Error("HF_API_KEY not set");
  const MODEL = "intfloat/multilingual-e5-large";
  const res = await fetch(
    `https://router.huggingface.co/hf-inference/models/${MODEL}/pipeline/feature-extraction`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${process.env.HF_API_KEY}` },
      body: JSON.stringify({ inputs: text }),
    }
  );
  if (!res.ok) throw new Error(`Embedding error ${res.status}: ${await res.text()}`);
  const data = await res.json();
  if (Array.isArray(data[0]) && Array.isArray(data[0][0])) return data[0][0];
  if (Array.isArray(data[0])) return data[0];
  return data;
}

// ── Pinecone helpers ────────────────────────────────────────────────────────
const ph = () => ({ "Api-Key": process.env.PINECONE_API_KEY, "Content-Type": "application/json" });

async function pineconeUpsert(vectors) {
  const res = await fetch(`${PINECONE_BASE_URL}/vectors/upsert`, {
    method: "POST", headers: ph(), body: JSON.stringify({ vectors }),
  });
  if (!res.ok) throw new Error(`Pinecone upsert ${res.status}: ${await res.text()}`);
  return res.json();
}

async function pineconeQuery(vector, topK = 9) {
  const res = await fetch(`${PINECONE_BASE_URL}/query`, {
    method: "POST", headers: ph(),
    body: JSON.stringify({ vector, topK, includeMetadata: true }),
  });
  if (!res.ok) throw new Error(`Pinecone query ${res.status}: ${await res.text()}`);
  return res.json();
}

async function pineconeDeleteAll() {
  const res = await fetch(`${PINECONE_BASE_URL}/vectors/delete`, {
    method: "POST", headers: ph(), body: JSON.stringify({ deleteAll: true }),
  });
  return res.ok;
}

export async function pineconeStats() {
  const res = await fetch(`${PINECONE_BASE_URL}/describe_index_stats`, { method: "GET", headers: ph() });
  if (!res.ok) return null;
  return res.json();
}

// ── Sync: scrape → embed → upsert ─────────────────────────────────────────
// Call POST /rag/sync whenever CIS publishes a new benchmark version.
// Just add the new URL to CIS_SOURCES above — no other code changes needed.
export async function sync() {
  console.log(`[RAG] Syncing ${CIS_SOURCES.length} CIS sources from web...`);

  const results = await Promise.all(CIS_SOURCES.map(scrapeSource));
  const chunks = results.filter(Boolean);
  console.log(`[RAG] Scraped ${chunks.length}/${CIS_SOURCES.length} controls`);

  if (chunks.length === 0) throw new Error("No CIS content scraped — check source URLs");

  // Clear stale vectors so updated controls replace old ones
  console.log("[RAG] Clearing old Pinecone vectors...");
  await pineconeDeleteAll();
  await new Promise(r => setTimeout(r, 2000));

  // Embed each chunk
  const vectors = [];
  for (const chunk of chunks) {
    try {
      const values = await embed(chunk.text);
      if (!Array.isArray(values) || values.length === 0) {
        console.error(`[RAG] Bad embedding for ${chunk.id}`); continue;
      }
      vectors.push({
        id: chunk.id,
        values,
        metadata: {
          control: chunk.control,
          title:   chunk.title,
          service: chunk.service,
          section: chunk.section,
          text:    chunk.text,
          source:  chunk.source,
        },
      });
      console.log(`[RAG] Embedded ${chunk.id} dim=${values.length}`);
      await new Promise(r => setTimeout(r, 300));
    } catch (e) {
      console.error(`[RAG] Embed failed ${chunk.id}:`, e.message);
    }
  }

  // Upsert in batches of 10
  for (let i = 0; i < vectors.length; i += 10) {
    try {
      await pineconeUpsert(vectors.slice(i, i + 10));
      console.log(`[RAG] Upserted batch ${Math.floor(i / 10) + 1}/${Math.ceil(vectors.length / 10)}`);
    } catch (e) {
      console.error(`[RAG] Upsert batch failed:`, e.message);
    }
  }

  const stats = await pineconeStats();
  console.log(`[RAG] Sync complete — ${stats?.totalVectorCount} vectors in Pinecone`);
  return {
    scraped:  chunks.length,
    embedded: vectors.length,
    stored:   stats?.totalVectorCount || 0,
    controls: chunks.map(c => ({ id: c.id, control: c.control, title: c.title, source: c.source })),
  };
}

// ── Retrieve relevant CIS controls for a query ─────────────────────────────
export async function retrieve(query, topK = 3, serviceFilter = null) {
  try {
    const embedding = await embed(query);
    const result = await pineconeQuery(embedding, topK * 3);
    let matches = result.matches || [];
    if (matches.length === 0) return "";

    console.log(`[RAG] Matches:`, matches.map(m => `${m.metadata.control}(${m.score?.toFixed(3)})`).join(", "));

    if (serviceFilter) {
      const filtered = matches.filter(m => m.metadata.service === serviceFilter);
      if (filtered.length > 0) matches = filtered;
    }

    return matches
      .slice(0, topK)
      .map(m => `[${m.metadata.control}] ${m.metadata.title}\nSource: ${m.metadata.source}\n\n${m.metadata.text}`)
      .join("\n\n---\n\n");
  } catch (e) {
    console.error("[RAG] Retrieval failed:", e.message);
    return "";
  }
}

// ── Health check ────────────────────────────────────────────────────────────
export async function ragHealthCheck() {
  try {
    const stats = await pineconeStats();
    return { ok: true, vectorCount: stats?.totalVectorCount || 0 };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}