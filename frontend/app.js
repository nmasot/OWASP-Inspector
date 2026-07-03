// =============================================
// CONFIG
// =============================================
// Usamos paths relativos porque el frontend y backend comparten el mismo puerto (8000)
const API_BASE = "";

// Helper centralizado para fetch: NO más cabeceras de autorización
function authHeaders(extra = {}) {
  return {
    "Content-Type": "application/json",
    ...extra,
  };
}

const OWASP_CHECKS = [
  "A01 · Broken Access Control",
  "A02 · Cryptographic Failures",
  "A03 · Injection",
  "A04 · Insecure Design",
  "A05 · Security Misconfiguration",
  "A06 · Vulnerable Components",
  "A07 · Auth Failures",
  "A08 · Data Integrity",
  "A09 · Logging & Monitoring",
  "A10 · SSRF",
];

// =============================================
// STATE
// =============================================
let currentMode = "passive";
let lastResults = null;
let lastTarget = "";
let lastAiPlan = "";

// =============================================
// INIT
// =============================================
document.getElementById("scan-year").textContent = new Date().getFullYear();
document.getElementById("scan-target").addEventListener("keydown", (e) => {
  if (e.key === "Enter") startScan();
});

// =============================================
// TAB NAVIGATION
// =============================================
function switchTab(tab) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.replace("flex", "hidden"));
  document.getElementById(`tab-${tab}`).classList.replace("hidden", "flex");
  
  document.querySelectorAll(".tab-btn").forEach((b) => {
    b.classList.remove("border-cyan-500", "text-cyan-500");
    b.classList.add("border-transparent", "text-slate-400");
  });
  event.currentTarget.classList.add("border-cyan-500", "text-cyan-500");
  event.currentTarget.classList.remove("border-transparent", "text-slate-400");
}

function setMode(mode) {
  currentMode = mode;
  document.getElementById("btn-passive").className = mode === "passive" ? "px-4 py-1.5 rounded-lg text-xs font-bold bg-cyan-500 text-slate-900" : "px-4 py-1.5 rounded-lg text-xs font-bold text-slate-400 hover:text-white";
  document.getElementById("btn-active").className = mode === "active" ? "px-4 py-1.5 rounded-lg text-xs font-bold bg-rose-500 text-white" : "px-4 py-1.5 rounded-lg text-xs font-bold text-slate-400 hover:text-white";
  
  if (mode === "active") {
    document.getElementById("consent-box").classList.replace("opacity-50", "opacity-100");
    document.getElementById("consent-cb").disabled = false;
  } else {
    document.getElementById("consent-box").classList.replace("opacity-100", "opacity-50");
    document.getElementById("consent-cb").disabled = true;
    document.getElementById("consent-cb").checked = false;
  }
}

// =============================================
// SCAN ENGINE
// =============================================
let progressInterval;

async function startScan() {
  const target = document.getElementById("scan-target").value;
  const consent = document.getElementById("consent-cb").checked;

  if (!target) return showToast("Debes ingresar un objetivo");
  if (currentMode === "active" && !consent) return showToast("Debes aceptar la política de riesgo para el modo ACTIVO");

  lastTarget = target;
  showProgress();
  animateProgress();

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ target, mode: currentMode, consent }),
    });

    if (res.status === 401) {
        cerrarSesionLocal();
        return;
    }

    const data = await res.json();
    lastResults = data.results;
    globalResults = data.results;
    lastAiPlan = data.ai_mitigation_plan;

    finishProgress();
    setTimeout(() => renderResults(data), 400);

  } catch (err) {
    clearInterval(progressInterval);
    document.getElementById("progress-label").textContent = "Error de conexión con el motor";
    document.getElementById("progress-bar").style.background = "#ef4444";
  }
}

// =============================================
// UI UPDATES
// =============================================
function showProgress() {
  document.getElementById("btn-scan").innerHTML = '<i class="fas fa-circle-notch fa-spin mr-2"></i> ESCANEANDO...';
  document.getElementById("btn-scan").disabled = true;
  document.getElementById("progress-bar").style.width = "0%";
  document.getElementById("progress-bar").style.background = "linear-gradient(90deg, #00f5ff, #7c3aed)";
  document.getElementById("ai-panel").classList.add("hidden");
}

function animateProgress() {
  let step = 0;
  const total = OWASP_CHECKS.length;

  progressInterval = setInterval(() => {
    if (step < total) {
      document.getElementById("progress-label").textContent = `Verificando ${OWASP_CHECKS[step]}...`;
      const pct = Math.round(((step + 1) / total) * 90);
      document.getElementById("progress-bar").style.width = pct + "%";
      step++;
    } else {
      clearInterval(progressInterval);
    }
  }, 900);
}

function finishProgress() {
  clearInterval(progressInterval);
  document.getElementById("progress-bar").style.width = "100%";
  document.getElementById("progress-label").textContent = "AUDITORÍA COMPLETADA";
  document.getElementById("btn-scan").innerHTML = "INICIAR ESCANEO";
  document.getElementById("btn-scan").disabled = false;
}

function renderResults(data) {
  OWASP_2025.forEach(cat => {
    const r = data.results.find(x => x.id.includes(cat.id));
    const card = document.getElementById(`card-${cat.id}`);
    const dot = document.getElementById(`dot-${cat.id}`);
    const statusText = document.getElementById(`status-${cat.id}`);
    const btn = document.getElementById(`btn-${cat.id}`);

    btn.classList.remove('opacity-0', 'pointer-events-none');

    if (r) {
      if (r.status === "VULNERABLE") {
        card.className = "card-owasp p-5 rounded-2xl flex flex-col justify-between min-h-[160px] border-rose-500/30 bg-rose-500/5";
        dot.className = "w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_10px_rgba(244,63,94,0.8)]";
        statusText.className = "text-[10px] mt-2 font-black uppercase tracking-widest text-rose-500";
        statusText.textContent = "VULNERABLE";
      } else if (r.status === "PASS") {
        card.className = "card-owasp p-5 rounded-2xl flex flex-col justify-between min-h-[160px] border-emerald-500/20 bg-emerald-500/5";
        dot.className = "w-2.5 h-2.5 rounded-full bg-emerald-500";
        statusText.className = "text-[10px] mt-2 font-black uppercase tracking-widest text-emerald-500";
        statusText.textContent = "SEGURO";
      } else {
        dot.className = "w-2.5 h-2.5 rounded-full bg-slate-500";
        statusText.textContent = "INFO / ERROR";
      }
    } else {
      dot.className = "w-2.5 h-2.5 rounded-full bg-slate-700";
      statusText.className = "text-[10px] mt-2 text-slate-600 font-bold uppercase tracking-tighter italic";
      statusText.textContent = "No evaluado";
    }
  });

  if (data.ai_mitigation_plan) {
    document.getElementById("ai-content").innerText = data.ai_mitigation_plan;
    document.getElementById("ai-panel").classList.remove("hidden");
  }
}

// =============================================
// TOAST NOTIFICATIONS
// =============================================
function showToast(msg, duration = 3000) {
  let toast = document.getElementById("toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "toast";
    toast.style.cssText = `
      position:fixed; bottom:20px; left:50%; transform:translateX(-50%) translateY(20px);
      background:#1e293b; color:#fff; padding:10px 20px; border-radius:8px;
      font-size:12px; font-weight:bold; box-shadow:0 10px 25px rgba(0,0,0,0.5);
      border: 1px solid #334155; z-index:9999; opacity:0; transition:all 0.3s ease; pointer-events:none;
      white-space:nowrap;
    `;
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateX(-50%) translateY(0)";
  });
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(-50%) translateY(20px)";
  }, duration);
}

// =============================================
// EXPORT PDF / JSON
// =============================================
function exportJSON() {
  if (!lastResults) return;
  const json = JSON.stringify(lastResults, null, 2);
  const dataUrl = "data:application/json;charset=utf-8," + encodeURIComponent(json);
  const a = document.createElement("a");
  a.href = dataUrl;
  a.download = `owasp-scan-${lastTarget.replace(/[^a-z0-9]/gi, "_")}-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

async function requestPDFExport() {
  if (!lastResults) return showToast("No hay resultados para exportar");

  showToast("Generando reporte PDF profesional...");
  
  try {
      const res = await fetch(`${API_BASE}/api/scan/report-pdf`, {
          method: "POST",
          headers: authHeaders(),
          body: JSON.stringify({
              target: lastTarget,
              mode: currentMode,
              results: globalResults,
              ai_plan: lastAiPlan || ""
          })
      });

      if (!res.ok) throw new Error("Fallo al generar PDF en el servidor");

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `Audit_OWASP_${lastTarget.replace(/[^a-z0-9]/gi, "_")}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      showToast("PDF descargado correctamente");
  } catch (error) {
      showToast(error.message);
  }
}