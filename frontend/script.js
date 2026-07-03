const OWASP_2025 = [
    { id: "A01", name: "Broken Access Control" }, { id: "A02", name: "Security Misconfiguration" },
    { id: "A03", name: "Software Supply Chain" }, { id: "A04", name: "Insecure Design" },
    { id: "A05", name: "Injection" }, { id: "A06", name: "Cryptographic Failures" },
    { id: "A07", name: "Identification & Auth" }, { id: "A08", name: "Software & Data Integrity" },
    { id: "A09", name: "Security Logging" }, { id: "A10", name: "Exceptional Conditions" }
];

let currentUsername = localStorage.getItem('owasp_inspector_user');
let globalResults = [];
let isRegisterMode = false;

async function checkSession() {
    if (currentUsername) {
        try {
            const res = await fetch('/api/auth/me'); 
            if (res.ok) {
                mostrarInterfazAuditor(currentUsername);
            } else if (res.status === 401) {
                cerrarSesionLocal();
            }
        } catch (error) {
            console.warn("Conexión interrumpida. Manteniendo UI activa...");
            mostrarInterfazAuditor(currentUsername);
        }
    }
}

function mostrarInterfazAuditor(user) {
    const auditorText = document.getElementById('current-auditor');
    if (auditorText) auditorText.innerText = user;
    
    const userControls = document.getElementById('user-controls');
    if (userControls) userControls.classList.replace('hidden', 'flex');
    
    const loginOverlay = document.getElementById('login-overlay');
    if (loginOverlay) loginOverlay.style.display = 'none';

    // Privilegios exclusivos del Administrador
    const btnAdmin = document.getElementById('btn-admin');
    const btnClear = document.getElementById('btn-clear-history');
    if (user.trim().toLowerCase() === 'admin') {
        if (btnAdmin) btnAdmin.classList.remove('hidden');
        if (btnClear) btnClear.classList.remove('hidden');
    } else {
        if (btnAdmin) btnAdmin.classList.add('hidden');
        if (btnClear) btnClear.classList.add('hidden');
    }
}

async function cerrarSesionLocal() {
    try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (e) {}
    localStorage.removeItem('owasp_inspector_user');
    currentUsername = null;
    location.reload();
}

function toggleMode() {
    isRegisterMode = !isRegisterMode;
    const title = document.getElementById('form-title') || document.getElementById('auth-title');
    const submitBtn = document.getElementById('submit-btn') || document.getElementById('auth-btn');
    const toggleBtn = document.getElementById('toggle-btn') || document.getElementById('auth-toggle');
    
    if (title) title.innerText = isRegisterMode ? 'REGISTRO DE NUEVO AUDITOR' : 'INICIAR SESIÓN';
    if (submitBtn) submitBtn.innerText = isRegisterMode ? 'REGISTRAR USUARIO' : 'INGRESAR AL MOTOR';
    if (toggleBtn) toggleBtn.innerText = isRegisterMode ? 'YA TIENES CUENTA? INGRESA AQUÍ' : 'REGISTRO DE NUEVO AUDITOR';
}

async function login(e) {
    if(e) e.preventDefault();
    const inputUser = document.getElementById('user') || document.getElementById('auth-user');
    const inputPass = document.getElementById('pass') || document.getElementById('auth-pass');
    
    if (!inputUser || !inputPass) return alert("Error de interfaz: campos de login no encontrados.");
    
    const u = inputUser.value.trim();
    const p = inputPass.value;

    if (isRegisterMode) {
        try {
            const res = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: u, password: p })
            });
            if (res.ok) {
                alert("Usuario registrado. Ahora inicia sesión.");
                toggleMode();
            } else {
                alert("Error al registrar: el usuario ya existe o hubo un fallo.");
            }
        } catch(e) { alert("Error de red."); }
    } else {
        const formData = new URLSearchParams();
        formData.append('username', u);
        formData.append('password', p);

        try {
            const res = await fetch('/api/auth/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData
            });
            const data = await res.json();
            
            if (res.ok) {
                localStorage.setItem('owasp_inspector_user', data.username);
                currentUsername = data.username;
                mostrarInterfazAuditor(data.username);
            } else {
                alert(`Credenciales incorrectas`);
            }
        } catch (error) {
            alert("Error de red al intentar iniciar sesión.");
        }
    }
}

function updateModeUI() {
    const modeInput = document.querySelector('input[name="mode"]:checked');
    if(!modeInput) return;
    const mode = modeInput.value;
    const lblPas = document.getElementById('lbl-passive');
    const lblAct = document.getElementById('lbl-active');
    const desc = document.getElementById('mode-desc');

    if(mode === 'passive') {
        if(lblPas) lblPas.className = 'cursor-pointer px-6 py-1.5 rounded-lg text-xs font-bold bg-cyan-600 text-white shadow-md transition-all';
        if(lblAct) lblAct.className = 'cursor-pointer px-6 py-1.5 rounded-lg text-xs font-bold text-slate-500 transition-all';
        if(desc) desc.innerText = 'Modo de solo lectura — No afecta la disponibilidad del servicio.';
    } else {
        if(lblAct) lblAct.className = 'cursor-pointer px-6 py-1.5 rounded-lg text-xs font-bold bg-rose-600 text-white shadow-md transition-all';
        if(lblPas) lblPas.className = 'cursor-pointer px-6 py-1.5 rounded-lg text-xs font-bold text-slate-500 transition-all';
        if(desc) desc.innerText = 'Escaneo intrusivo — Ejecuta payloads de ataque (Requiere Autorización).';
    }
}

function initGrid() {
    const grid = document.getElementById('grid-owasp');
    if (!grid) return;
    grid.innerHTML = '';
    OWASP_2025.forEach(cat => {
        grid.innerHTML += `
            <div id="card-${cat.id}" class="card-owasp p-5 rounded-2xl flex flex-col justify-between min-h-[140px]">
                <div>
                    <div class="flex items-center gap-2 mb-3">
                        <div class="w-2.5 h-2.5 rounded-full bg-slate-700" id="dot-${cat.id}"></div>
                        <h4 class="text-[10px] uppercase font-black text-slate-500 tracking-widest">${cat.id}</h4>
                    </div>
                    <h3 class="text-xs font-bold text-slate-200 leading-snug">${cat.name}</h3>
                    <p id="status-${cat.id}" class="text-[10px] mt-2 text-slate-600 font-bold uppercase tracking-tighter italic">En espera...</p>
                </div>
                <button onclick="showModal('${cat.id}', '${cat.name}')" class="mt-4 text-[10px] font-black text-cyan-500 hover:text-cyan-300 transition-all uppercase hidden flex items-center gap-1.5" id="btn-detail-${cat.id}">
                    <i class="fas fa-plus-circle"></i> Análisis
                </button>
            </div>
        `;
    });
}

async function runScan() {
    const targetEl = document.getElementById('target') || document.getElementById('scan-target');
    const target = targetEl ? targetEl.value : "";
    
    const modeInput = document.querySelector('input[name="mode"]:checked');
    const mode = modeInput ? modeInput.value : "passive";
    
    if(!target) return alert("Ingresa un objetivo.");

    const btn = document.getElementById('btn-scan');
    if(btn) { btn.disabled = true; btn.innerText = "Escaneando..."; }
    
    const resultsContainer = document.getElementById('results-container');
    if (resultsContainer) resultsContainer.classList.remove('hidden');
    
    initGrid();
    globalResults = [];

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, mode, consent: mode === 'active' })
        });
        
        if (response.status === 401) {
            return cerrarSesionLocal();
        }
        
        const data = await response.json();
        
        if (data.results && Array.isArray(data.results)) {
            data.results.sort((a, b) => a.id.localeCompare(b.id));
        }

        globalResults = data.results;
        renderResults(data.results);
        
        if (data.ai_mitigation_plan) {
            const aiContent = document.getElementById('ai-content');
            const aiPanel = document.getElementById('ai-panel');
            if(aiContent) aiContent.innerText = data.ai_mitigation_plan;
            if(aiPanel) aiPanel.classList.remove('hidden');
        }

    } catch (err) {
        console.warn("Aviso de red durante escaneo:", err);
    } finally { 
        if(btn) { btn.disabled = false; btn.innerText = "Iniciar Escaneo"; }
    }
}

function renderResults(results) {
    let high = 0, med = 0, low = 0;
    results.forEach(res => {
        const catId = res.id.split('-')[0];
        const statusEl = document.getElementById(`status-${catId}`);
        const dotEl = document.getElementById(`dot-${catId}`);
        const btnDetail = document.getElementById(`btn-detail-${catId}`);
        
        if (!statusEl) return;
        if (btnDetail) btnDetail.classList.remove('hidden');

        if (res.status === "VULNERABLE") {
            statusEl.innerText = "Vulnerable";
            statusEl.className = "text-[10px] mt-2 font-black text-rose-500 uppercase italic";
            if(dotEl) dotEl.className = "w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_12px_#f43f5e]";
            if(res.severity === "HIGH" || res.severity === "CRITICAL") high++;
            else if(res.severity === "MEDIUM") med++;
            else low++;
        } else if (res.status === "PASS") {
            if (!statusEl.classList.contains('text-rose-500')) {
                statusEl.innerText = "Seguro";
                statusEl.className = "text-[10px] mt-2 font-black text-emerald-500 uppercase italic";
                if(dotEl) dotEl.className = "w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-[0_0_12px_#10b981]";
            }
        }
    });

    const stats = document.getElementById('stats-summary');
    if(stats) {
        stats.innerHTML = `
            <div class="px-5 py-2 bg-rose-500/10 border border-rose-500/20 rounded-2xl flex flex-col items-center">
                <span class="text-[9px] font-black text-rose-500/60 uppercase">Crítico</span>
                <span class="text-lg font-black text-rose-500">${high}</span>
            </div>
            <div class="px-5 py-2 bg-amber-500/10 border border-amber-500/20 rounded-2xl flex flex-col items-center">
                <span class="text-[9px] font-black text-amber-500/60 uppercase">Medio</span>
                <span class="text-lg font-black text-amber-500">${med}</span>
            </div>
            <div class="px-5 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-2xl flex flex-col items-center">
                <span class="text-[9px] font-black text-emerald-500/60 uppercase">Bajo</span>
                <span class="text-lg font-black text-emerald-500">${low}</span>
            </div>
        `;
    }
}

function showModal(catId, catName) {
    const modal = document.getElementById('modal-details');
    const content = document.getElementById('modal-content');
    if(!modal || !content) return;

    document.getElementById('modal-title').innerText = `${catId} — ${catName}`;
    content.innerHTML = ''; 

    const findings = globalResults.filter(r => r.id.startsWith(catId));

    if (findings.length === 0) {
        content.innerHTML = '<div class="text-center py-10"><i class="fas fa-search text-4xl text-slate-800 mb-4"></i><p class="text-slate-500 text-sm font-bold uppercase">Sin datos</p></div>';
    } else {
        findings.forEach(f => {
            let colorCode = "border-emerald-500/30 bg-emerald-500/5 text-emerald-400"; 
            if (f.status === "VULNERABLE") colorCode = "border-rose-500/30 bg-rose-500/5 text-rose-400";

            content.innerHTML += `
                <div class="p-5 rounded-2xl border ${colorCode.split(' ')[0]} ${colorCode.split(' ')[1]} mb-4">
                    <div class="flex justify-between items-center mb-4">
                        <h4 class="font-black text-xs uppercase tracking-tight text-white">${f.name}</h4>
                        <span class="text-[9px] font-black px-2.5 py-1 rounded-md border ${colorCode}">${f.status}</span>
                    </div>
                    <div class="space-y-4">
                        <div>
                            <span class="text-[9px] font-black text-slate-500 uppercase block mb-1.5"><i class="fas fa-fingerprint text-cyan-500"></i> Evidencia</span>
                            <pre class="bg-black/40 p-3 rounded-xl text-xs text-rose-200 font-mono border border-white/5 overflow-x-auto whitespace-pre-wrap">${f.details}</pre>
                        </div>
                        <div>
                            <span class="text-[9px] font-black text-slate-500 uppercase block mb-1.5"><i class="fas fa-tools text-emerald-500"></i> Mitigación</span>
                            <p class="text-[11px] text-slate-300 bg-slate-800/50 p-3 rounded-xl border border-white/5">${f.remediation}</p>
                        </div>
                    </div>
                </div>
            `;
        });
    }
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeModal() {
    const modal = document.getElementById('modal-details');
    if(modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

function downloadJSON() {
    if (globalResults.length === 0) return alert("Sin datos.");
    const targetEl = document.getElementById('target') || document.getElementById('scan-target');
    const target = targetEl ? targetEl.value.replace(/[^a-zA-Z0-9]/g, '_') : 'scan';
    const blob = new Blob([JSON.stringify(globalResults, null, 4)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Audit_OWASP_Inspector_${target}.json`;
    a.click();
}

function downloadPDF() {
    if (globalResults.length === 0) return alert("Sin datos.");
    const targetEl = document.getElementById('target') || document.getElementById('scan-target');
    const target = targetEl ? targetEl.value : "";
    const modeInput = document.querySelector('input[name="mode"]:checked');
    const mode = modeInput ? modeInput.value : "passive";
    const aiContent = document.getElementById('ai-content');
    
    fetch('/api/scan/report-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            target: target,
            mode: mode,
            results: globalResults,
            ai_plan: aiContent ? aiContent.innerText : ""
        })
    })
    .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.blob();
    })
    .then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Audit_OWASP_${target.replace(/[^a-zA-Z0-9]/g, '_')}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
    })
    .catch(err => alert("Error descargando PDF: " + err.message));
}

function cerrarSesion() {
    if(confirm("¿Estás seguro de que deseas cerrar sesión?")) cerrarSesionLocal();
}

async function verHistorial() {
    const tbody = document.getElementById('history-table-body');
    const emptyState = document.getElementById('history-empty');
    if(tbody) tbody.innerHTML = '<tr><td colspan="4" class="text-center py-4"><i class="fas fa-spinner fa-spin text-cyan-500"></i> Cargando...</td></tr>';
    if(emptyState) emptyState.classList.add('hidden');
    
    const modal = document.getElementById('modal-history');
    if(modal) { modal.classList.remove('hidden'); modal.classList.add('flex'); }

    try {
        const response = await fetch('/api/history');
        if (response.status === 401) return cerrarSesion();
        
        const data = await response.json();
        if(tbody) tbody.innerHTML = '';
        
        if (data.length === 0) {
            if(emptyState) emptyState.classList.remove('hidden');
        } else {
            data.forEach(scan => {
                const dateObj = new Date(scan.date);
                const formattedDate = dateObj.toLocaleDateString() + ' ' + dateObj.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                const modeColor = scan.mode === 'active' ? 'text-rose-400' : 'text-cyan-400';
                
                if(tbody) {
                    tbody.innerHTML += `
                        <tr class="hover:bg-slate-800/30 transition-colors">
                            <td class="px-4 py-4 whitespace-nowrap text-xs">${formattedDate}</td>
                            <td class="px-4 py-4 text-xs font-mono text-slate-300">${scan.target}</td>
                            <td class="px-4 py-4 whitespace-nowrap text-[10px] font-black uppercase ${modeColor}">${scan.mode}</td>
                            <td class="px-4 py-4 whitespace-nowrap">
                                <div class="flex gap-2">
                                    <span class="px-2 py-0.5 bg-rose-500/10 text-rose-500 border border-rose-500/20 rounded text-[10px] font-bold">${scan.critical_vulns}</span>
                                    <span class="px-2 py-0.5 bg-orange-500/10 text-orange-400 border border-orange-500/20 rounded text-[10px] font-bold">${scan.high_vulns}</span>
                                    <span class="px-2 py-0.5 bg-amber-500/10 text-amber-500 border border-amber-500/20 rounded text-[10px] font-bold">${scan.medium_vulns}</span>
                                </div>
                            </td>
                        </tr>
                    `;
                }
            });
        }
    } catch (e) {
        if(tbody) tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-rose-500 text-xs">Error cargando historial</td></tr>`;
    }
}

function closeHistoryModal() {
    const modal = document.getElementById('modal-history');
    if(modal) { modal.classList.add('hidden'); modal.classList.remove('flex'); }
}

async function borrarHistorial() {
    if(!confirm("¿Estás seguro de borrar TODO el historial del sistema? Esta acción es irreversible.")) return;
    try {
        const res = await fetch('/api/history', { method: 'DELETE' });
        if(res.ok) verHistorial();
        else alert("Acceso denegado.");
    } catch(e) { console.error(e); }
}

async function openAdminModal() {
    const modal = document.getElementById('modal-admin');
    if(modal) { modal.classList.remove('hidden'); modal.classList.add('flex'); }
    loadUsers();
}

function closeAdminModal() {
    const modal = document.getElementById('modal-admin');
    if(modal) { modal.classList.add('hidden'); modal.classList.remove('flex'); }
}

async function loadUsers() {
    const tbody = document.getElementById('admin-users-body');
    if(!tbody) return;
    tbody.innerHTML = '<tr><td colspan="3" class="text-center py-4"><i class="fas fa-spinner fa-spin text-cyan-500"></i></td></tr>';
    try {
        const res = await fetch('/api/users');
        if(!res.ok) throw new Error("No autorizado");
        const users = await res.json();
        tbody.innerHTML = '';
        users.forEach(u => {
            const isAdm = u.username === 'admin';
            tbody.innerHTML += `
                <tr class="hover:bg-slate-800/30 transition-colors">
                    <td class="px-4 py-3 text-xs">${u.id}</td>
                    <td class="px-4 py-3 text-xs font-bold text-white">${u.username} ${isAdm ? '<span class="ml-2 text-[8px] bg-rose-500 px-1.5 py-0.5 rounded text-white">ROOT</span>' : ''}</td>
                    <td class="px-4 py-3 text-right">
                        <button onclick="document.getElementById('admin-user-name').value='${u.username}'; document.getElementById('admin-user-pass').focus();" class="text-cyan-500 hover:text-cyan-400 mr-3" title="Editar Contraseña"><i class="fas fa-edit"></i></button>
                        ${!isAdm ? `<button onclick="adminDeleteUser('${u.username}')" class="text-rose-500 hover:text-rose-400" title="Eliminar"><i class="fas fa-trash"></i></button>` : ''}
                    </td>
                </tr>
            `;
        });
    } catch(e) { tbody.innerHTML = '<tr><td colspan="3" class="text-center py-4 text-rose-500">Acceso denegado</td></tr>'; }
}

async function adminSaveUser() {
    const u = document.getElementById('admin-user-name').value;
    const p = document.getElementById('admin-user-pass').value;
    if(!u || !p) return alert("Completa usuario y contraseña");
    
    const resCreate = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p })
    });
    
    if(resCreate.ok) {
        alert("Usuario creado exitosamente.");
        document.getElementById('admin-user-pass').value = '';
        loadUsers();
    } else if (resCreate.status === 400) {
        const resEdit = await fetch(`/api/users/${u}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: u, password: p })
        });
        if(resEdit.ok) {
            alert("Contraseña actualizada exitosamente.");
            document.getElementById('admin-user-pass').value = '';
            loadUsers();
        } else alert("Error al actualizar contraseña.");
    }
}

async function adminDeleteUser(username) {
    if(!confirm(`¿Estás seguro de eliminar permanentemente al usuario ${username}?`)) return;
    const res = await fetch(`/api/users/${username}`, { method: 'DELETE' });
    if(res.ok) loadUsers();
    else alert("Error al borrar usuario");
}

document.addEventListener('DOMContentLoaded', () => {
    initGrid();
    checkSession();
});