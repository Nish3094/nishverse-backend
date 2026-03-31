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
// Model: intfloat/multilingual-e5-large — 1024 dimensions, officially supported by HF hf-inference
// Get free token: https://huggingface.co/settings/tokens (read token is enough)
async function embed(text) {
  if (!process.env.HF_API_KEY) {
    throw new Error("HF_API_KEY environment variable is not set.");
  }

  const MODEL = "intfloat/multilingual-e5-large";  // 1024 dimensions — officially supported by HF inference
  const res = await fetch(
    `https://router.huggingface.co/hf-inference/models/${MODEL}/pipeline/feature-extraction`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.HF_API_KEY}`,
      },
      body: JSON.stringify({ inputs: text }),
    }
  );

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Embedding error ${res.status}: ${err}`);
  }

  const data = await res.json();

  // HF returns nested array for single string input — unwrap one level
  if (Array.isArray(data[0]) && Array.isArray(data[0][0])) return data[0][0];
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

  // Log raw Pinecone stats so we can see what the index reports
  const stats = await pineconeStats();
  console.log(`[RAG] Pinecone stats:`, JSON.stringify(stats));
  const vectorCount = stats?.totalVectorCount || 0;
  if (vectorCount >= CIS_CONTROLS.length) {
    console.log(`[RAG] Index already has ${vectorCount} vectors — skipping ingest.`);
    return { skipped: true, vectorCount };
  }

  // Test embedding on first control before processing all
  console.log(`[RAG] Testing embed on first control...`);
  try {
    const testEmbed = await embed(CIS_CONTROLS[0].text);
    console.log(`[RAG] Embed test OK — type: ${typeof testEmbed}, isArray: ${Array.isArray(testEmbed)}, length: ${Array.isArray(testEmbed) ? testEmbed.length : "N/A"}, sample: ${Array.isArray(testEmbed) ? testEmbed.slice(0,3) : testEmbed}`);
  } catch (e) {
    console.error(`[RAG] Embed test FAILED:`, e.message);
    return { error: e.message };
  }

  const vectors = [];
  for (const control of CIS_CONTROLS) {
    try {
      const embedding = await embed(control.text);
      if (!Array.isArray(embedding) || embedding.length === 0) {
        console.error(`[RAG] Bad embedding for ${control.id}: not an array or empty. Got:`, typeof embedding, JSON.stringify(embedding)?.slice(0, 100));
        continue;
      }
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
      console.log(`[RAG] Embedded ${control.id}: dim=${embedding.length}`);
      await new Promise(r => setTimeout(r, 300));
    } catch (e) {
      console.error(`[RAG] Failed to embed ${control.id}:`, e.message);
    }
  }

  console.log(`[RAG] Embedding done. ${vectors.length}/${CIS_CONTROLS.length} succeeded. Upserting...`);

  if (vectors.length === 0) {
    console.error(`[RAG] No vectors to upsert — aborting.`);
    return { error: "No vectors produced" };
  }

  // Upsert in batches of 10
  const batchSize = 10;
  for (let i = 0; i < vectors.length; i += batchSize) {
    const batch = vectors.slice(i, i + batchSize);
    try {
      const result = await pineconeUpsert(batch);
      console.log(`[RAG] Upserted batch ${Math.floor(i / batchSize) + 1}:`, JSON.stringify(result));
    } catch (e) {
      console.error(`[RAG] Upsert batch ${Math.floor(i / batchSize) + 1} FAILED:`, e.message);
    }
  }

  const finalStats = await pineconeStats();
  console.log(`[RAG] Final Pinecone stats:`, JSON.stringify(finalStats));
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
