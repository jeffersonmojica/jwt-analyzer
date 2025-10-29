// Configuración de la API
const API_BASE = window.location.origin;
const API_URL = `${API_BASE}/api`;

// Estado global
let currentAnalysis = null;

// ============== INICIALIZACIÓN ==============
document.addEventListener('DOMContentLoaded', () => {
    initializeTabs();
    initializeEventListeners();
    loadTestCases();
    checkAPIHealth();
});

// Verificar que la API esté funcionando
async function checkAPIHealth() {
    try {
        const response = await fetch(`${API_URL}/health`);
        const data = await response.json();
        console.log('✅ API Status:', data.message);
    } catch (error) {
        console.error('❌ API no disponible:', error);
        showError('No se puede conectar con el servidor. Verifica que el backend esté ejecutándose.');
    }
}

// ============== TABS ==============
function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.dataset.tab;

            // Remover active de todos
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            // Activar el seleccionado
            button.classList.add('active');
            document.getElementById(tabName).classList.add('active');

            // Cargar contenido según la pestaña
            if (tabName === 'tests') {
                loadTestCases();
            } else if (tabName === 'history') {
                loadHistory();
            } else if (tabName === 'stats') {
                loadStatistics();
            }
        });
    });
}

// ============== EVENT LISTENERS ==============
function initializeEventListeners() {
    // Botón analizar
    document.getElementById('analyze-btn').addEventListener('click', analyzeJWT);

    // Botón codificar
    document.getElementById('encode-btn').addEventListener('click', encodeJWT);

    // Botón actualizar historial
    document.getElementById('refresh-history-btn').addEventListener('click', loadHistory);

    // Botón actualizar estadísticas
    document.getElementById('refresh-stats-btn').addEventListener('click', loadStatistics);

    // Enter en inputs
    document.getElementById('jwt-input').addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'Enter') {
            analyzeJWT();
        }
    });
}

// ============== ANALIZAR JWT ==============
async function analyzeJWT() {
    const token = document.getElementById('jwt-input').value.trim();
    const secret = document.getElementById('secret-input').value.trim();
    const resultsArea = document.getElementById('results-area');

    if (!token) {
        showError('Por favor ingresa un token JWT');
        return;
    }

    if (!secret) {
        showError('Por favor ingresa una clave secreta');
        return;
    }

    // Mostrar loading
    resultsArea.innerHTML = `
        <div class="card loading">
            <i class="fas fa-spinner fa-spin"></i> Analizando token...
        </div>
    `;

    try {
        const response = await fetch(`${API_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ token, secret })
        });

        const data = await response.json();

        if (data.success) {
            currentAnalysis = data;
            displayAnalysisResults(data);
        } else {
            resultsArea.innerHTML = `
                <div class="alert alert-error">
                    <i class="fas fa-times-circle"></i>
                    <div>
                        <strong>Error en el análisis:</strong><br>
                        ${data.error}
                    </div>
                </div>
            `;
        }
    } catch (error) {
        resultsArea.innerHTML = `
            <div class="alert alert-error">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong>Error de conexión:</strong><br>
                    ${error.message}
                </div>
            </div>
        `;
    }
}

// ============== MOSTRAR RESULTADOS DEL ANÁLISIS ==============
function displayAnalysisResults(data) {
    const resultsArea = document.getElementById('results-area');
    const phases = data.phases;

    let html = '';

    // Resumen general
    html += `
        <div class="card">
            <h2><i class="fas fa-check-circle"></i> Resumen del Análisis</h2>
            ${data.is_valid ? 
                '<div class="alert alert-success"><i class="fas fa-check-circle"></i> <strong>Token Válido ✓</strong></div>' :
                '<div class="alert alert-error"><i class="fas fa-times-circle"></i> <strong>Token Inválido ✗</strong></div>'
            }
            <div class="grid-2">
                <div class="result-card">
                    <div style="color: var(--danger); font-size: 2rem; font-weight: bold;">${data.summary.total_errors}</div>
                    <div style="color: var(--gray);">Errores Encontrados</div>
                </div>
                <div class="result-card">
                    <div style="color: var(--warning); font-size: 2rem; font-weight: bold;">${data.summary.total_warnings}</div>
                    <div style="color: var(--gray);">Advertencias</div>
                </div>
            </div>
        </div>
    `;

    // Fase 1: Análisis Léxico
    html += `
        <div class="card result-card">
            <div class="phase-header">
                <i class="fas fa-code" style="color: var(--primary); font-size: 1.5rem;"></i>
                <h3>Fase 1: Análisis Léxico</h3>
            </div>
            <p style="color: var(--gray); margin-bottom: 15px;">
                Tokenización del JWT - Identificación de componentes
            </p>
    `;

    phases.phase1_lexical.tokens.forEach((token, idx) => {
        html += `
            <div class="token-item">
                <div class="token-type">Token ${idx + 1}: ${token.type}</div>
                ${token.type !== 'SEPARATOR' ? 
                    `<div class="token-value">${token.value.substring(0, 60)}${token.value.length > 60 ? '...' : ''}</div>
                     <div style="color: var(--gray); font-size: 0.8rem; margin-top: 5px;">
                        Posición: ${token.position} | Longitud: ${token.length}
                     </div>` : 
                    `<div class="token-value">Separador: "${token.value}"</div>`
                }
            </div>
        `;
    });

    html += `</div>`;

    // Fase 4: Decodificación
    html += `
        <div class="card result-card">
            <div class="phase-header">
                <i class="fas fa-unlock" style="color: var(--success); font-size: 1.5rem;"></i>
                <h3>Fase 4: Decodificación (Base64URL)</h3>
            </div>
            <div class="grid-2">
                <div>
                    <h4><i class="fas fa-file-code"></i> Header Decodificado</h4>
                    <div class="json-display">
                        <pre>${JSON.stringify(phases.phase4_decoded.header, null, 2)}</pre>
                    </div>
                </div>
                <div>
                    <h4><i class="fas fa-database"></i> Payload Decodificado</h4>
                    <div class="json-display">
                        <pre>${JSON.stringify(phases.phase4_decoded.payload, null, 2)}</pre>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Fase 2: Análisis Sintáctico
    html += `
        <div class="card result-card">
            <div class="phase-header">
                <i class="fas fa-project-diagram" style="color: var(--info); font-size: 1.5rem;"></i>
                <h3>Fase 2: Análisis Sintáctico</h3>
            </div>
    `;

    if (phases.phase2_syntactic.valid) {
        html += `
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <div><strong>Sintaxis Válida</strong> - Estructura JSON correcta en Header y Payload</div>
            </div>
        `;
    } else {
        html += '<div><h4 style="color: var(--danger);">Errores Sintácticos:</h4>';
        phases.phase2_syntactic.errors.forEach(error => {
            html += `
                <div class="alert alert-error">
                    <i class="fas fa-times-circle"></i>
                    <div>${error}</div>
                </div>
            `;
        });
        html += '</div>';
    }

    html += `</div>`;

    // Fase 3: Análisis Semántico
    html += `
        <div class="card result-card">
            <div class="phase-header">
                <i class="fas fa-brain" style="color: var(--secondary); font-size: 1.5rem;"></i>
                <h3>Fase 3: Análisis Semántico</h3>
            </div>
    `;

    // Errores semánticos
    if (phases.phase3_semantic.errors.length > 0) {
        html += '<h4 style="color: var(--danger);"><i class="fas fa-exclamation-circle"></i> Errores Semánticos:</h4>';
        phases.phase3_semantic.errors.forEach(error => {
            html += `
                <div class="alert alert-error">
                    <i class="fas fa-times-circle"></i>
                    <div>${error}</div>
                </div>
            `;
        });
    }

    // Advertencias
    if (phases.phase3_semantic.warnings.length > 0) {
        html += '<h4 style="color: var(--warning); margin-top: 15px;"><i class="fas fa-exclamation-triangle"></i> Advertencias:</h4>';
        phases.phase3_semantic.warnings.forEach(warning => {
            html += `
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>${warning}</div>
                </div>
            `;
        });
    }

    // Sin errores ni advertencias
    if (phases.phase3_semantic.errors.length === 0 && phases.phase3_semantic.warnings.length === 0) {
        html += `
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <div><strong>Análisis Semántico Exitoso</strong> - Todos los campos son válidos</div>
            </div>
        `;
    }

    // Tabla de símbolos
    html += `
        <h4 style="margin-top: 20px;"><i class="fas fa-table"></i> Tabla de Símbolos</h4>
        <div style="overflow-x: auto;">
            <table class="table">
                <thead>
                    <tr>
                        <th>Símbolo</th>
                        <th>Tipo</th>
                        <th>Valor</th>
                        <th>Info</th>
                    </tr>
                </thead>
                <tbody>
    `;

    for (const [key, data] of Object.entries(phases.phase3_semantic.symbol_table)) {
        const isStandard = data.standard ? '<span class="badge badge-valid">Estándar</span>' : '';
        const isCustom = data.custom ? '<span class="badge badge-semantic">Personalizado</span>' : '';
        const isRequired = data.required ? '<span class="badge badge-valid">Requerido</span>' : '';

        html += `
            <tr>
                <td style="font-family: 'Courier New', monospace; color: var(--primary);">${key}</td>
                <td>${data.type}</td>
                <td style="max-width: 300px; word-break: break-all;">${JSON.stringify(data.value)}</td>
                <td>${isStandard}${isCustom}${isRequired}</td>
            </tr>
        `;
    }

    html += `
                </tbody>
            </table>
        </div>
    </div>
    `;

    // Fase 6: Verificación Criptográfica
    html += `
        <div class="card result-card">
            <div class="phase-header">
                <i class="fas fa-shield-alt" style="color: var(--warning); font-size: 1.5rem;"></i>
                <h3>Fase 6: Verificación Criptográfica</h3>
            </div>
            
            <div class="result-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <div>
                        <strong style="color: var(--gray);">Algoritmo:</strong> 
                        <span style="font-family: 'Courier New', monospace; color: var(--primary); font-size: 1.2rem;">
                            ${phases.phase6_signature.algorithm}
                        </span>
                    </div>
                    <div>
                        ${phases.phase6_signature.valid ? 
                            '<span class="badge badge-valid" style="font-size: 1rem; padding: 8px 20px;">✓ FIRMA VÁLIDA</span>' :
                            '<span class="badge badge-malformed" style="font-size: 1rem; padding: 8px 20px;">✗ FIRMA INVÁLIDA</span>'
                        }
                    </div>
                </div>
    `;

    if (phases.phase6_signature.valid) {
        html += `
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <div>
                    <strong>Firma Válida</strong><br>
                    La firma criptográfica del token es correcta y el token no ha sido modificado.
                </div>
            </div>
        `;
    } else {
        html += `
            <div class="alert alert-error">
                <i class="fas fa-times-circle"></i>
                <div>
                    <strong>Firma Inválida</strong><br>
                    ${phases.phase6_signature.error || phases.phase6_signature.message || 'La firma no coincide con el contenido del token'}
                </div>
            </div>
        `;

        if (phases.phase6_signature.expected_signature) {
            html += `
                <div style="margin-top: 15px; font-size: 0.9rem;">
                    <div style="margin-bottom: 8px;">
                        <strong style="color: var(--success);">Firma Esperada:</strong><br>
                        <code style="color: var(--gray); word-break: break-all;">${phases.phase6_signature.expected_signature}</code>
                    </div>
                    <div>
                        <strong style="color: var(--danger);">Firma Recibida:</strong><br>
                        <code style="color: var(--gray); word-break: break-all;">${phases.phase6_signature.received_signature}</code>
                    </div>
                </div>
            `;
        }
    }

    html += `
            </div>
        </div>
    `;

    resultsArea.innerHTML = html;
}

// ============== CODIFICAR JWT ==============
async function encodeJWT() {
    const headerText = document.getElementById('header-input').value;
    const payloadText = document.getElementById('payload-input').value;
    const secret = document.getElementById('secret-encode').value.trim();
    const resultsArea = document.getElementById('encode-results');

    if (!secret) {
        showError('Por favor ingresa una clave secreta');
        return;
    }

    // Validar JSON
    let header, payload;
    try {
        header = JSON.parse(headerText);
        payload = JSON.parse(payloadText);
    } catch (e) {
        resultsArea.innerHTML = `
            <div class="alert alert-error">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong>Error de JSON:</strong><br>
                    Verifica que el Header y Payload sean JSON válidos
                </div>
            </div>
        `;
        return;
    }

    resultsArea.innerHTML = `
        <div class="card loading">
            <i class="fas fa-spinner fa-spin"></i> Generando JWT...
        </div>
    `;

    try {
        const response = await fetch(`${API_URL}/encode`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ header, payload, secret })
        });

        const data = await response.json();

        if (data.success) {
            resultsArea.innerHTML = `
                <div class="card">
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        <div><strong>JWT Generado Exitosamente</strong></div>
                    </div>

                    <h3><i class="fas fa-key"></i> Token JWT</h3>
                    <div class="json-display" style="background: rgba(16, 185, 129, 0.1); border: 2px solid var(--success);">
                        <pre style="color: #fff; word-break: break-all; white-space: pre-wrap;">${data.token}</pre>
                    </div>

                    <div style="margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap;">
                        <button onclick="copyToClipboard('${data.token}')" class="btn btn-success">
                            <i class="fas fa-copy"></i> Copiar al Portapapeles
                        </button>
                        <button onclick="loadTokenToDecoder('${data.token}')" class="btn btn-secondary">
                            <i class="fas fa-search"></i> Analizar Este Token
                        </button>
                    </div>

                    <div class="grid-2" style="margin-top: 25px;">
                        <div>
                            <h4><i class="fas fa-info-circle"></i> Header</h4>
                            <div class="json-display">
                                <pre>${JSON.stringify(data.header, null, 2)}</pre>
                            </div>
                        </div>
                        <div>
                            <h4><i class="fas fa-database"></i> Payload</h4>
                            <div class="json-display">
                                <pre>${JSON.stringify(data.payload, null, 2)}</pre>
                            </div>
                        </div>
                    </div>

                    <div style="margin-top: 15px; padding: 15px; background: rgba(99, 102, 241, 0.1); border-radius: 8px;">
                        <strong style="color: var(--primary);">Algoritmo:</strong> ${data.algorithm}<br>
                        <strong style="color: var(--primary);">ID en Base de Datos:</strong> ${data.token_id}
                    </div>
                </div>
            `;
        } else {
            resultsArea.innerHTML = `
                <div class="alert alert-error">
                    <i class="fas fa-times-circle"></i>
                    <div>
                        <strong>Error:</strong><br>
                        ${data.error}
                    </div>
                </div>
            `;
        }
    } catch (error) {
        resultsArea.innerHTML = `
            <div class="alert alert-error">
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <strong>Error de conexión:</strong><br>
                    ${error.message}
                </div>
            </div>
        `;
    }
}

// ============== CASOS DE PRUEBA ==============
async function loadTestCases() {
    const testCasesArea = document.getElementById('test-cases-area');

    testCasesArea.innerHTML = `
        <div class="loading">
            <i class="fas fa-spinner fa-spin"></i> Cargando casos de prueba...
        </div>
    `;

    try {
        const response = await fetch(`${API_URL}/test-cases`);
        const data = await response.json();

        if (data.success) {
            let html = '';

            data.test_cases.forEach(testCase => {
                const badgeClass = {
                    'valid': 'badge-valid',
                    'temporal': 'badge-expired',
                    'syntax': 'badge-malformed',
                    'semantic': 'badge-semantic',
                    'cryptographic': 'badge-malformed'
                }[testCase.category] || 'badge-semantic';

                html += `
                    <div class="test-case-card">
                        <div class="test-case-header">
                            <div>
                                <div class="test-case-title">
                                    <i class="fas fa-flask"></i> ${testCase.name}
                                </div>
                                <span class="badge ${badgeClass}">${testCase.category}</span>
                                <span class="badge badge-semantic">${testCase.expected_result}</span>
                            </div>
                            <button onclick="loadTestCase('${testCase._id}')" class="btn btn-primary btn-small">
                                <i class="fas fa-play"></i> Cargar y Probar
                            </button>
                        </div>
                        <div class="test-case-description">${testCase.description}</div>
                        <div class="test-case-token">${testCase.token}</div>
                        <div style="margin-top: 10px; font-size: 0.85rem; color: var(--gray);">
                            <strong>Clave secreta:</strong> <code>${testCase.secret}</code>
                        </div>
                    </div>
                `;
            });

            testCasesArea.innerHTML = html;
        } else {
            testCasesArea.innerHTML = `
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-triangle"></i>
                    <div>Error cargando casos de prueba</div>
                </div>
            `;
        }
    } catch (error) {
        testCasesArea.innerHTML = `
            <div class="alert alert-error">
                <i class="fas fa-exclamation-triangle"></i>
                <div>Error de conexión: ${error.message}</div>
            </div>
        `;
    }
}
async function loadTestCase(testCaseId) {
    try {
        const response = await fetch(`${API_URL}/test-cases`);
        const data = await response.json();

        const testCase = data.test_cases.find(tc => tc._id === testCaseId);

        if (testCase) {
            // Cargar token Y clave secreta
            document.getElementById('jwt-input').value = testCase.token;
            document.getElementById('secret-input').value = testCase.secret;  // ← ESTA LÍNEA ES CLAVE

            // Cambiar a tab de decodificador
            document.querySelector('[data-tab="decoder"]').click();

            // Analizar automáticamente después de un pequeño delay
            setTimeout(() => {
                analyzeJWT();
            }, 300);
        }
    } catch (error) {
        console.error('Error loading test case:', error);
    }
}

// ============== HISTORIAL ==============
async function loadHistory() {
    const historyArea = document.getElementById('history-area');

    historyArea.innerHTML = `
        <div class="loading">
            <i class="fas fa-spinner fa-spin"></i> Cargando historial...
        </div>
    `;

    try {
        const response = await fetch(`${API_URL}/history?limit=20`);
        const data = await response.json();

        if (data.success && data.analyses.length > 0) {
            let html = '<div class="card"><table class="table"><thead><tr>';
            html += '<th>Fecha</th>';
            html += '<th>Token (Preview)</th>';
            html += '<th>Estado</th>';
            html += '<th>Errores</th>';
            html += '<th>Advertencias</th>';
            html += '</tr></thead><tbody>';

            data.analyses.forEach(analysis => {
                const date = new Date(analysis.created_at).toLocaleString('es-CO');
                const statusIcon = analysis.is_valid ? 
                    '<span class="badge badge-valid"><i class="fas fa-check"></i> Válido</span>' :
                    '<span class="badge badge-malformed"><i class="fas fa-times"></i> Inválido</span>';

                html += `
                    <tr>
                        <td>${date}</td>
                        <td style="font-family: 'Courier New', monospace; font-size: 0.8rem;">${analysis.token}</td>
                        <td>${statusIcon}</td>
                        <td><span class="badge" style="background: var(--danger);">${analysis.summary.total_errors}</span></td>
                        <td><span class="badge" style="background: var(--warning);">${analysis.summary.total_warnings}</span></td>
                    </tr>
                `;
            });

            html += '</tbody></table></div>';
            historyArea.innerHTML = html;
        } else {
            historyArea.innerHTML = `
                <div class="card">
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle"></i>
                        <div>No hay análisis en el historial aún. Comienza analizando algunos tokens.</div>
                    </div>
                </div>
            `;
        }
    } catch (error) {
        historyArea.innerHTML = `
            <div class="alert alert-error">
                <i class="fas fa-exclamation-triangle"></i>
                <div>Error cargando historial: ${error.message}</div>
            </div>
        `;
    }
}

// ============== ESTADÍSTICAS ==============
async function loadStatistics() {
    const statsArea = document.getElementById('stats-area');

    statsArea.innerHTML = `
        <div class="loading">
            <i class="fas fa-spinner fa-spin"></i> Cargando estadísticas...
        </div>
    `;

    try {
        const response = await fetch(`${API_URL}/statistics`);
        const data = await response.json();

        if (data.success) {
            const stats = data.statistics;

            statsArea.innerHTML = `
                <div class="stats-grid">
                    <div class="stat-card">
                        <i class="fas fa-chart-line" style="font-size: 2rem; color: var(--primary);"></i>
                        <div class="stat-value">${stats.total_analyses}</div>
                        <div class="stat-label">Total Análisis</div>
                    </div>
                    <div class="stat-card">
                        <i class="fas fa-check-circle" style="font-size: 2rem; color: var(--success);"></i>
                        <div class="stat-value">${stats.valid_tokens}</div>
                        <div class="stat-label">Tokens Válidos</div>
                    </div>
                    <div class="stat-card">
                        <i class="fas fa-times-circle" style="font-size: 2rem; color: var(--danger);"></i>
                        <div class="stat-value">${stats.invalid_tokens}</div>
                        <div class="stat-label">Tokens Inválidos</div>
                    </div>
                    <div class="stat-card">
                        <i class="fas fa-percentage" style="font-size: 2rem; color: var(--info);"></i>
                        <div class="stat-value">${stats.success_rate.toFixed(1)}%</div>
                        <div class="stat-label">Tasa de Éxito</div>
                    </div>
                </div>

                <div class="card" style="margin-top: 20px;">
                    <h3><i class="fas fa-info-circle"></i> Información del Sistema</h3>
                    <div style="color: var(--gray); line-height: 1.8;">
                        <p><i class="fas fa-server"></i> <strong>Backend:</strong> Flask + Python</p>
                        <p><i class="fas fa-database"></i> <strong>Base de Datos:</strong> MongoDB Atlas</p>
                        <p><i class="fas fa-shield-alt"></i> <strong>Algoritmos Soportados:</strong> HS256, HS384, HS512</p>
                        <p><i class="fas fa-check"></i> <strong>Estado:</strong> Sistema Operativo</p>
                    </div>
                </div>
            `;
        }
    } catch (error) {
        statsArea.innerHTML = `
            <div class="alert alert-error">
                <i class="fas fa-exclamation-triangle"></i>
                <div>Error cargando estadísticas: ${error.message}</div>
            </div>
        `;
    }
}

// ============== UTILIDADES ==============
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showSuccess('Token copiado al portapapeles');
    }).catch(() => {
        showError('No se pudo copiar el token');
    });
}

function loadTokenToDecoder(token) {
    document.getElementById('jwt-input').value = token;
    document.querySelector('[data-tab="decoder"]').click();
    setTimeout(() => {
        document.getElementById('jwt-input').scrollIntoView({ behavior: 'smooth' });
    }, 100);
}

function showError(message) {
    const resultsArea = document.getElementById('results-area');
    resultsArea.innerHTML = `
        <div class="alert alert-error">
            <i class="fas fa-exclamation-triangle"></i>
            <div>${message}</div>
        </div>
    `;
}

function showSuccess(message) {
    // Crear notificación temporal
    const notification = document.createElement('div');
    notification.className = 'alert alert-success';
    notification.style.position = 'fixed';
    notification.style.top = '20px';
    notification.style.right = '20px';
    notification.style.zIndex = '9999';
    notification.style.animation = 'fadeIn 0.3s ease';
    notification.innerHTML = `
        <i class="fas fa-check-circle"></i>
        <div>${message}</div>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 3000);
}