# app.py
import os
import time
import io
import hmac
import hashlib
from dataclasses import dataclass
from typing import Optional, Tuple, List

import streamlit as st
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# ---------------------------------------------------------------------
# Config & reproducibility
# ---------------------------------------------------------------------
st.set_page_config(page_title="PROMPT MAESTRO — Mini-Lab IoT (Integridad & Capas)",
                   layout="wide",
                   initial_sidebar_state="expanded")
np.random.seed(7)

# Obtain HMAC secret from Streamlit Secrets (recommended) or fallback
_secret_raw = st.secrets.get("HMAC_SECRET", None)
if _secret_raw is None:
    # pedagogical fallback: generate ephemeral secret (not for production)
    SECRET = os.urandom(16)
else:
    # if provided as string in secrets, treat as text key
    SECRET = _secret_raw.encode("utf-8")

# ---------------------------------------------------------------------
# Utility: hashing functions
# ---------------------------------------------------------------------
def sha256_str(msg: bytes) -> str:
    return hashlib.sha256(msg).hexdigest()

def hmac_sha256(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

# ---------------------------------------------------------------------
# Channel class (simulated)
# ---------------------------------------------------------------------
@dataclass
class Canal:
    loss_prob: float = 0.0
    latency_ms_range: Tuple[int, int] = (10, 200)
    tamper_bias: float = 0.0  # degrees C bias added when tampering
    tamper_on: bool = False

    def transmit(self, payload_temp: float) -> Optional[float]:
        # Simulate packet loss
        if np.random.rand() < self.loss_prob:
            return None
        # Simulate tampering
        rx = payload_temp
        if self.tamper_on and self.tamper_bias != 0:
            # Tamper by adding bias with small noise
            rx = rx + self.tamper_bias + np.random.normal(scale=0.2)
        # Simulate latency (we return value immediately; latency could be logged)
        simulated_latency = np.random.randint(self.latency_ms_range[0], self.latency_ms_range[1] + 1)
        return rx

# ---------------------------------------------------------------------
# Helper: format for download
# ---------------------------------------------------------------------
def create_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8")

# ---------------------------------------------------------------------
# UI: Title and description
# ---------------------------------------------------------------------
st.title("PROMPT MAESTRO — Mini-Lab IoT: Integridad (HMAC) & Capas")
st.markdown("""
**Objetivo:** experimentar cómo un hash simple (SHA-256) puede fallar al detectar manipulación en entornos con pérdida/latencia, y cómo **HMAC-SHA256** (con clave secreta) proporciona verificación robusta.  
También comparar protocolos IoT (BW/latencia/consumo) en la Pestaña *Capas IoT*.
""")

# Sidebar quick info
with st.sidebar:
    st.header("Info rápida")
    st.markdown(
        "- Reproducibilidad: `np.random.seed(7)`\n"
        "- Secrets: añadir `HMAC_SECRET=\"cambia-esta-clave\"` en App settings → Secrets (opcional)\n"
        "- Matplotlib para gráficos (sin seaborn)\n"
    )
    st.markdown("**Nota de seguridad pedagógica:** La clave HMAC debe guardarse en *secrets* del servidor. En producción NUNCA en el cliente ni en el repo.")

# ---------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------
tab1, tab2, tab3 = st.tabs(["Sesión 1 — Integridad (HMAC)", "Sesión 2 — Capas IoT", "Caso & Entregables"])

# -------------------------
# SESIÓN 1 - Integridad
# -------------------------
with tab1:
    st.header("Sesión 1 — Simulación de sensor + canal + verificación")
    col_controls, col_vis = st.columns([1, 2])

    with col_controls:
        st.subheader("Controles de simulación")
        dur = st.slider("Duración (s)", min_value=5, max_value=60, value=15, step=1, help="Duración total de la simulación")
        loss = st.slider("Prob. pérdida (0–0.30)", min_value=0.0, max_value=0.30, value=0.05, step=0.01)
        tamper_on = st.checkbox("Tampering ON", value=False)
        tamper_bias = st.slider("tamper_bias (°C) — sesgo de manipulación (opcional)", 5, 20, 8) if st.checkbox("Activar selector tamper_bias (extensión)") else 8
        verify_method = st.selectbox("Verificación", options=["None", "SHA", "HMAC"], index=2)
        export_csv_opt = st.checkbox("Habilitar botón Exportar CSV (muestras recibidas)", value=True)
        run_sim = st.button("Ejecutar simulación")

        st.markdown("---")
        st.markdown("**Clave usada (solo para demostración):**")
        if _secret_raw is None:
            st.info("No hay HMAC_SECRET en Secrets. Usando clave generada temporalmente (no persistente).")
        else:
            st.success("HMAC_SECRET encontrado en Secrets (clave usada en la comprobación).")

    with col_vis:
        st.subheader("Gráfico tiempo real (temperaturas)")

        # placeholders
        fig_placeholder = st.empty()
        stats_placeholder = st.empty()
        csv_bytes = None

        # Initialize session state lists
        if "temps" not in st.session_state:
            st.session_state["temps"] = []
            st.session_state["times"] = []
            st.session_state["sent_hashes"] = []
            st.session_state["recv_hashes"] = []
            st.session_state["fail_flags"] = []

        # Prepare sensor baseline (noise + drift)
        base_temp = 25.0  # °C
        drift_per_s = 0.005  # small drift

        if run_sim:
            # Reset previous results
            st.session_state["temps"] = []
            st.session_state["times"] = []
            st.session_state["sent_hashes"] = []
            st.session_state["recv_hashes"] = []
            st.session_state["fail_flags"] = []

            canal = Canal(loss_prob=loss, latency_ms_range=(10, 200), tamper_bias=float(tamper_bias), tamper_on=tamper_on)

            t0 = time.time()
            elapsed = 0.0
            sample_time = 0.0
            dt = 0.25  # sampling every ~0.25 s => 4 Hz
            total_samples = int(max(1, dur / dt))

            # For plotting
            times = []
            temps = []
            fails = []

            for i in range(total_samples):
                # Sensor: generate reading with some noise and drift
                sample_time = time.time() - t0
                true_temp = base_temp + drift_per_s * sample_time + np.random.normal(scale=0.3)
                # Sender computes hash (or hmac) over the numeric payload (as bytes)
                payload = f"{true_temp:.4f}".encode("utf-8")
                if verify_method == "SHA":
                    sent_tag = sha256_str(payload)
                elif verify_method == "HMAC":
                    sent_tag = hmac_sha256(SECRET, payload)
                else:
                    sent_tag = ""  # no tag

                # Transmit via channel
                rx = canal.transmit(true_temp)

                # If packet lost, mark as None and skip verification
                if rx is None:
                    # append None as missing
                    st.session_state["times"].append(sample_time)
                    st.session_state["temps"].append(None)
                    st.session_state["sent_hashes"].append(sent_tag)
                    st.session_state["recv_hashes"].append(None)
                    st.session_state["fail_flags"].append(False)  # not a verification failure, just loss
                else:
                    # receiver recomputes hash from received payload (note: tampering will alter rx)
                    recv_payload = f"{rx:.4f}".encode("utf-8")
                    if verify_method == "SHA":
                        recv_tag = sha256_str(recv_payload)
                    elif verify_method == "HMAC":
                        recv_tag = hmac_sha256(SECRET, recv_payload)
                    else:
                        recv_tag = ""

                    # Integrity check: compare tags
                    if verify_method in ("SHA", "HMAC"):
                        integrity_fail = (sent_tag != recv_tag)
                    else:
                        integrity_fail = False

                    st.session_state["times"].append(sample_time)
                    st.session_state["temps"].append(rx)
                    st.session_state["sent_hashes"].append(sent_tag)
                    st.session_state["recv_hashes"].append(recv_tag)
                    st.session_state["fail_flags"].append(integrity_fail)

                # Live plotting: update every iteration
                # Prepare data for plot (filter None)
                plot_times = [t for t, val in zip(st.session_state["times"], st.session_state["temps"]) if val is not None]
                plot_vals = [val for val in st.session_state["temps"] if val is not None]
                fail_x = [t for t, f, val in zip(st.session_state["times"], st.session_state["fail_flags"], st.session_state["temps"]) if f and (val is not None)]
                fail_y = [val for f, val in zip(st.session_state["fail_flags"], st.session_state["temps"]) if f and (val is not None)]

                fig, ax = plt.subplots(figsize=(9, 3.5))
                ax.plot(plot_times, plot_vals, marker="o", linestyle="-", label="Temp (°C)")
                if len(fail_x) > 0:
                    ax.scatter(fail_x, fail_y, color="red", s=40, label="Fallo integridad", zorder=5)
                ax.set_xlabel("Tiempo (s)")
                ax.set_ylabel("Temperatura (°C)")
                ax.grid(True)
                ax.legend(loc="upper left")
                fig.tight_layout()

                fig_placeholder.pyplot(fig)
                plt.close(fig)

                # Stats
                total_samples_seen = len(st.session_state["times"])
                total_losses = sum(1 for v in st.session_state["temps"] if v is None)
                total_failures = sum(1 for f in st.session_state["fail_flags"] if f)
                stats_placeholder.markdown(
                    f"**Samples:** {total_samples_seen} &nbsp;&nbsp;|&nbsp;&nbsp; **Pérdidas:** {total_losses} &nbsp;&nbsp;|&nbsp;&nbsp; **Fallos integridad:** {total_failures} &nbsp;&nbsp;|&nbsp;&nbsp; **Tampering:** {'ON' if tamper_on else 'OFF'} &nbsp;&nbsp;|&nbsp;&nbsp; **Verif.:** {verify_method}"
                )

                # small sleep to simulate real-time sampling
                time.sleep(dt)

            # After loop: prepare CSV of received samples (option)
            df = pd.DataFrame({
                "time_s": st.session_state["times"],
                "temp_received": st.session_state["temps"],
                "sent_tag": st.session_state["sent_hashes"],
                "recv_tag": st.session_state["recv_hashes"],
                "integrity_fail": st.session_state["fail_flags"]
            })
            csv_bytes = create_csv_bytes(df)

            if export_csv_opt:
                st.download_button("Exportar CSV de muestras recibidas", data=csv_bytes, file_name="muestras_sesion1.csv", mime="text/csv")

            # Final textual explanation / what to observe
            st.markdown("### Qué observar")
            st.markdown("""
            - **SHA-256 (sin clave)**: si el atacante puede alterar el payload y recomputar la **misma** función hash antes de enviarlo, el receptor verá un hash que *coincide* — por tanto SHA alone no garantiza integridad contra un atacante activo que puede recomputar el hash.  
            - **HMAC-SHA256**: requiere una clave secreta que el atacante **no** conoce. Si el atacante manipula el payload sin conocer la clave, no podrá recomputar el HMAC correcto y la verificación fallará.  
            - En el experimento, activa **Tampering ON** y compara los fallos con **SHA** vs **HMAC**.
            """)
        else:
            st.info("Pulse 'Ejecutar simulación' para comenzar. Ajusta duración, pérdida y tampering.")
            st.caption("Sugerencia: prueba `Tampering ON + HMAC` para ver puntos rojos (fallos de integridad).")

# -------------------------
# SESIÓN 2 - Capas IoT
# -------------------------
with tab2:
    st.header("Sesión 2 — Comparativa de capas/protocolos IoT")
    st.markdown("Selecciona protocolo, nº de sensores y si activas alertas. Calcularemos BW requerido vs disponible, latencia y consumo aproximado y un score heurístico.")

    col_a, col_b = st.columns(2)
    with col_a:
        protocol = st.selectbox("Protocolo", ["WiFi", "LoRaWAN", "Zigbee", "NB-IoT"])
        n_sensors = st.slider("Número de sensores", min_value=1, max_value=20, value=5)
        alerts_on = st.checkbox("Alertas (on/off)", value=True)

    with col_b:
        st.markdown("**Parámetros didácticos (valores aproximados)**")
        st.write("Se usan valores pedagógicos aproximados para comparar comportamientos típicos.")

    # Protocol characteristics (didácticos)
    protocols_info = {
        "WiFi": {"bw_kbps": 10000, "latency_ms": 20, "energy_mw_per_sensor": 200},
        "LoRaWAN": {"bw_kbps": 50, "latency_ms": 1000, "energy_mw_per_sensor": 5},
        "Zigbee": {"bw_kbps": 250, "latency_ms": 100, "energy_mw_per_sensor": 20},
        "NB-IoT": {"bw_kbps": 200, "latency_ms": 200, "energy_mw_per_sensor": 50},
    }

    info = protocols_info[protocol]
    bw_available = info["bw_kbps"]
    latency_ms = info["latency_ms"]
    energy_mw = info["energy_mw_per_sensor"]

    # Assumption: each sensor requires 2 kbps (didáctico)
    bw_per_sensor = 2  # kbps
    bw_required = bw_per_sensor * n_sensors
    ok_bw = bw_available >= bw_required

    # Heuristic score (0-100)
    # Components: BW match (0-1), latency normalized (lower better), energy normalized (lower better)
    bw_score = min(1.0, bw_available / (bw_required if bw_required>0 else 1))
    latency_norm = min(1.0, latency_ms / 2000.0)  # larger latency -> worse
    energy_norm = min(1.0, energy_mw / 500.0)
    score = int(100 * bw_score * (1 - latency_norm) * (1 - energy_norm))
    score = max(0, score)

    st.subheader("Resultados")
    st.metric("BW disponible (kbps)", bw_available)
    st.metric("BW requerido (kbps)", bw_required)
    st.metric("Latencia aproximada (ms)", latency_ms)
    st.metric("Consumo aprox. por sensor (mW)", energy_mw)
    st.metric("Score heurístico (0-100)", score)

    st.markdown("**¿BW suficiente?** " + ("✅ Sí" if ok_bw else "❌ No"))

    # Bar chart: BW requerido vs disponible (matplotlib)
    fig2, ax2 = plt.subplots(figsize=(6,3))
    categories = ["Requerido", "Disponible"]
    values = [bw_required, bw_available]
    ax2.bar(categories, values)
    ax2.set_ylabel("kbps")
    ax2.set_title(f"BW Requerido vs Disponible — {protocol} — {n_sensors} sensores")
    ax2.grid(axis="y", linestyle="--", alpha=0.4)
    st.pyplot(fig2)
    plt.close(fig2)

    st.markdown("### Explicación breve (docente)")
    st.markdown("""
    - **WiFi:** alto BW y baja latencia — bueno para streaming y grandes volúmenes, pero mayor consumo energético.  
    - **LoRaWAN:** muy eficiente en energía y largo alcance, pero muy limitado en BW y alta latencia — apto para telemetría esporádica.  
    - **Zigbee:** compromiso para redes de sensores locales con moderado BW y latencia media.  
    - **NB-IoT:** mejor cobertura celular para baja tasa de datos, latencia moderada y consumo medio.
    """)

# -------------------------
# TAB 3 - Caso & Entregables
# -------------------------
with tab3:
    st.header("Caso & Entregables")
    st.markdown("Indicaciones para los alumnos: realizar ambas sesiones y subir evidencias según se pide.")

    st.markdown("**Instrucciones de entrega**")
    st.markdown("""
    - **Sesión 1 (Integridad):**
      1. Ejecutar la simulación con **Tampering ON** y **Verificación = HMAC**.  
      2. Tomar una captura de pantalla donde se vean **puntos rojos** (fallos de integridad) y el resumen con nº de fallos.  
      3. Subir la captura y escribir **3 líneas de reflexión** sobre por qué HMAC detecta la manipulación y por qué SHA podría fallar.

    - **Sesión 2 (Capas IoT):**
      1. Ejecutar combinaciones con un protocolo (WiFi/LoRaWAN/Zigbee/NB-IoT) y un nº de sensores.  
      2. Tomar captura del *bar chart* BW requerido vs disponible.  
      3. Subir la captura y añadir **3 líneas justificando** el trade-off latencia/energía elegido.
    """)

    st.markdown("**Material de caso**")
    st.markdown("Si tienes `docs/caso.pdf` en el repo, la app enlazará a ese PDF. Si no, utiliza el caso de estudio subido por el docente (archivo Word).")
    st.markdown("Caso de estudio (documento proporcionado):")
    st.caption("Referencia del caso subido por el usuario (puedes convertirlo a docs/caso.pdf y añadirlo al repo).")
    st.markdown("**Referencia al documento subido:** :contentReference[oaicite:1]{index=1}")

    st.markdown("---")
    st.markdown("**Entrega (formato sugerido):** zip o carpeta en el LMS con las dos capturas y el texto con las 3 líneas por sesión.")

    st.markdown("**Notas docentes rápidas:**")
    st.markdown("""
    - Explicar que **la clave HMAC debe permanecer secreta** y alojada en *Streamlit Secrets* o KMS.  
    - SHA sin clave garantiza integridad frente a errores aleatorios, **no** frente a un atacante activo que pueda recalcular el hash.  
    - Este mini-lab es didáctico: los valores (BW, latencia, energía) son aproximados para comparación.
    """)

# ---------------------------------------------------------------------
# Footer / quick help
# ---------------------------------------------------------------------
st.sidebar.markdown("---")
st.sidebar.markdown("**Prueba rápida** en la UI: ver README para pasos rápidos.")
