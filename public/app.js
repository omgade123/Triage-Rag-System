// Triage RAG System — frontend logic (vanilla JS, no build step).

const form = document.getElementById("triage-form");
const submitBtn = document.getElementById("submit-btn");
const spinner = submitBtn.querySelector(".spinner");
const btnLabel = submitBtn.querySelector(".btn-label");
const placeholder = document.getElementById("placeholder");
const output = document.getElementById("output");
const errorBox = document.getElementById("error");

const SAMPLE = {
  title: "Stored XSS via unsanitized profile display name",
  description:
    "The application stores a user-supplied display name and renders it " +
    "without output encoding on the public profile page. An attacker can set " +
    "their display name to a script payload, which then executes in the " +
    "browser of any user who views the profile, allowing session hijacking.",
  cwe: "",
};

// --- Health check ---
async function checkHealth() {
  const dot = document.getElementById("health-dot");
  const text = document.getElementById("health-text");
  try {
    const res = await fetch("/health");
    if (!res.ok) throw new Error();
    dot.className = "dot ok";
    text.textContent = "API online";
  } catch {
    dot.className = "dot down";
    text.textContent = "API offline";
  }
}

// --- Sample loader ---
document.getElementById("sample-btn").addEventListener("click", () => {
  document.getElementById("title").value = SAMPLE.title;
  document.getElementById("description").value = SAMPLE.description;
  document.getElementById("cwe").value = SAMPLE.cwe;
});

// --- Submit ---
form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const title = document.getElementById("title").value.trim();
  const description = document.getElementById("description").value.trim();
  const cwe = document.getElementById("cwe").value.trim();
  if (!title || !description) return;

  setLoading(true);
  hide(errorBox);

  try {
    const res = await fetch("/triage/classify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, description, cwe: cwe || undefined }),
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(
        data?.error?.formErrors?.join(", ") ||
          data?.error ||
          `Request failed (${res.status})`
      );
    }

    render(data);
  } catch (err) {
    showError(err.message || "Something went wrong.");
  } finally {
    setLoading(false);
  }
});

function setLoading(loading) {
  submitBtn.disabled = loading;
  spinner.hidden = !loading;
  btnLabel.textContent = loading ? "Triaging…" : "Triage report";
}

function hide(el) {
  el.hidden = true;
}

function showError(msg) {
  hide(placeholder);
  hide(output);
  errorBox.textContent = msg;
  errorBox.hidden = false;
}

// --- Render results ---
function render(data) {
  hide(placeholder);
  hide(errorBox);
  output.hidden = false;

  renderDuplicateBanner(data);
  renderClassification(data.classification);
  renderCandidates(data.candidates || []);
}

function renderDuplicateBanner(data) {
  const banner = document.getElementById("dup-banner");
  if (data.isDuplicate && data.topMatch) {
    const pct = (data.topMatch.similarity * 100).toFixed(1);
    banner.className = "banner dup";
    banner.textContent = `⚠ Likely duplicate of ${data.topMatch.id} (${pct}% similar)`;
  } else {
    banner.className = "banner clean";
    banner.textContent = "✓ No likely duplicate found above threshold";
  }
}

function renderClassification(c) {
  const chips = document.getElementById("pred-chips");
  const rationale = document.getElementById("rationale");
  const citations = document.getElementById("citations");

  if (!c) {
    chips.innerHTML = "";
    rationale.textContent = "No classification returned.";
    citations.innerHTML = "";
    return;
  }

  const cwe = c.predictedCwe || "unknown";
  const sev = c.predictedSeverity || "unknown";
  const sevClass = c.predictedSeverity ? `sev-${c.predictedSeverity}` : "";
  const confClass = `conf-${c.confidence}`;

  chips.innerHTML = `
    <span class="chip"><span class="k">CWE</span>${escapeHtml(cwe)}</span>
    <span class="chip ${sevClass}"><span class="k">Severity</span>${escapeHtml(
    sev
  )}</span>
    <span class="chip"><span class="k">Confidence</span><span class="${confClass}">${escapeHtml(
    c.confidence
  )}</span></span>
  `;

  rationale.textContent = c.rationale || "";

  if (c.citations && c.citations.length) {
    citations.innerHTML = c.citations
      .map(
        (cite) => `
        <div class="citation">
          <span class="cite-id">${escapeHtml(cite.reportId)}</span> —
          ${escapeHtml(cite.reason)}
        </div>`
      )
      .join("");
  } else {
    citations.innerHTML =
      '<div class="citation">No grounding citations — treat prediction with caution.</div>';
  }
}

function renderCandidates(candidates) {
  const list = document.getElementById("candidates");
  const count = document.getElementById("candidate-count");
  count.textContent = candidates.length ? `(${candidates.length})` : "";

  if (!candidates.length) {
    list.innerHTML =
      '<li class="candidate">No similar reports found. Has the database been seeded?</li>';
    return;
  }

  list.innerHTML = candidates
    .map((c) => {
      const pct = (c.similarity * 100).toFixed(1);
      return `
      <li class="candidate">
        <div class="cand-head">
          <span class="cand-id">${escapeHtml(c.id)}</span>
          <span class="cand-meta">
            <span>${escapeHtml(c.cwe || "—")}</span>
            <span>${escapeHtml(c.severity || "—")}</span>
          </span>
        </div>
        <p class="cand-desc">${escapeHtml(c.description || "")}</p>
        <div class="simbar"><span style="width:${pct}%"></span></div>
        <div class="sim-label">${pct}% similar</div>
      </li>`;
    })
    .join("");
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

checkHealth();
