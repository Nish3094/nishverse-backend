// ── RAG Module ─────────────────────────────────────────────────────────────
// Embeds CIS benchmark chunks using Groq (via a lightweight embedding model)
// and stores/queries them in Pinecone for retrieval-augmented generation.
//
// Flow:
//   ingest()  → chunks CIS controls → embeds → upserts to Pinecone
//   retrieve() → embeds query → queries Pinecone → returns top-k chunks

import CIS_CONTROLS from "./cis-knowledge.js";

const PINECONE_API_KEY  = process.env.PINECONE_API_KEY;
const PINECONE_INDEX    = process.env.PINECONE_INDEX || "nishverse-cis";
const PINECONE_BASE_URL = process.env.PINECONE_INDEX_HOST; // e.g. https://nishverse-cis-xxxx.svc.pinecone.io

// ── Embedding via Hugging Face Inference API (free, no credit card) ────────
// Model: nomic-ai/nomic-embed-text-v1.5 — 768 dimensions, great for RAG
// Get free token: https://huggingface.co/settings/tokens (read token is enough)
async function embed(text) {
  if (!process.env.HF_API_KEY) {
    throw new Error("HF_API_KEY environment variable is not set.");
  }

  const res = await fetch(
    "https://router.huggingface.co/pipeline/feature-extraction/nomic-ai/nomic-embed-text-v1.5",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.HF_API_KEY}`,
      },
      body: JSON.stringify({
        inputs: text,
        options: { wait_for_model: true },
      }),
    }
  );

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Embedding error ${res.status}: ${err}`);
  }

  const data = await res.json();

  // HF returns either a flat array (single input) or nested array
  if (Array.isArray(data[0])) return data[0];
  return data;
}

// ── Pinecone helpers ────────────────────────────────────────────────────────
function pineconeHeaders() {
  return {
    "Api-Key": PINECONE_API_KEY,
    "Content-Type": "application/json",
  };
}

async function pineconeUpsert(vectors) {
  const res = await fetch(`${PINECONE_BASE_URL}/vectors/upsert`, {
    method: "POST",
    headers: pineconeHeaders(),
    body: JSON.stringify({ vectors }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Pinecone upsert error ${res.status}: ${err}`);
  }
  return res.json();
}

async function pineconeQuery(vector, topK = 3, filter = {}) {
  const body = { vector, topK, includeMetadata: true };
  if (Object.keys(filter).length > 0) body.filter = filter;

  const res = await fetch(`${PINECONE_BASE_URL}/query`, {
    method: "POST",
    headers: pineconeHeaders(),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Pinecone query error ${res.status}: ${err}`);
  }
  return res.json();
}

async function pineconeStats() {
  const res = await fetch(`${PINECONE_BASE_URL}/describe_index_stats`, {
    method: "GET",
    headers: pineconeHeaders(),
  });
  if (!res.ok) return null;
  return res.json();
}

// ── Ingest: embed all CIS controls and upsert to Pinecone ──────────────────
// Call this once (or on deploy) to populate the index.
export async function ingest() {
  console.log(`[RAG] Starting ingestion of ${CIS_CONTROLS.length} CIS controls...`);

  // Check if already ingested
  const stats = await pineconeStats();
  const vectorCount = stats?.totalVectorCount || 0;
  if (vectorCount >= CIS_CONTROLS.length) {
    console.log(`[RAG] Index already has ${vectorCount} vectors — skipping ingest.`);
    return { skipped: true, vectorCount };
  }

  const vectors = [];
  for (const control of CIS_CONTROLS) {
    try {
      const embedding = await embed(control.text);
      vectors.push({
        id: control.id,
        values: embedding,
        metadata: {
          control: control.control,
          title:   control.title,
          service: control.service,
          section: control.section,
          text:    control.text,
        },
      });
      console.log(`[RAG] Embedded: ${control.id} (${control.control})`);
      // Small delay to avoid rate limiting
      await new Promise(r => setTimeout(r, 200));
    } catch (e) {
      console.error(`[RAG] Failed to embed ${control.id}:`, e.message);
    }
  }

  // Upsert in batches of 10
  const batchSize = 10;
  for (let i = 0; i < vectors.length; i += batchSize) {
    const batch = vectors.slice(i, i + batchSize);
    await pineconeUpsert(batch);
    console.log(`[RAG] Upserted batch ${Math.floor(i / batchSize) + 1}`);
  }

  console.log(`[RAG] Ingestion complete. ${vectors.length} vectors stored.`);
  return { ingested: vectors.length };
}

// ── Retrieve: find the most relevant CIS controls for a given finding ───────
// Returns the top-k CIS control texts to inject into AI prompts.
export async function retrieve(query, topK = 2, serviceFilter = null) {
  try {
    const queryEmbedding = await embed(query);
    const filter = serviceFilter ? { service: { $eq: serviceFilter } } : {};
    const result = await pineconeQuery(queryEmbedding, topK, filter);

    const matches = result.matches || [];
    if (matches.length === 0) return "";

    return matches
      .map(m => `[${m.metadata.control}] ${m.metadata.title}\n${m.metadata.text}`)
      .join("\n\n---\n\n");
  } catch (e) {
    console.error("[RAG] Retrieval failed:", e.message);
    return ""; // Gracefully degrade — AI still responds without RAG context
  }
}

// ── Health check: verify Pinecone + Groq embeddings are working ─────────────
export async function ragHealthCheck() {
  try {
    const stats = await pineconeStats();
    return {
      ok: true,
      vectorCount: stats?.totalVectorCount || 0,
      indexName: PINECONE_INDEX,
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}
