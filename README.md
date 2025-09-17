# iot-integridad-lab

Mini-Lab didáctico en Streamlit: **Integridad (HMAC)** y **Capas IoT** — listo para desplegar desde GitHub → Streamlit Community Cloud (100% web).

## Contenido
- `app.py` — aplicación Streamlit con las dos sesiones interactivas.
- `requirements.txt` — dependencias necesarias.
- `README.md` — esta guía.
- `docs/caso.pdf` — (opcional) caso de estudio en PDF. Si no está, el docente puede incluir el `docx` original.

**Documento de caso (proporcionado por el usuario):** :contentReference[oaicite:2]{index=2}

---

## Objetivos docentes
1. Entender la diferencia entre **hash** simple y **HMAC** para detectar manipulación activa.  
2. Comparar protocolos IoT (BW/latencia/consumo) y aprender trade-offs prácticos.

---

## Pasos para desplegar en Streamlit Cloud (sin usar CLI)

1. Crear un nuevo repositorio en GitHub llamado `iot-integridad-lab`.
2. Copiar/pegar **exactamente** los archivos `app.py`, `requirements.txt`, `README.md` (y opcionalmente `docs/caso.pdf`) en el repo usando la **web UI** de GitHub.
3. Ir a **https://share.streamlit.io** → **New app** → conectar GitHub → seleccionar tu repo y rama.
4. En "Main file" seleccionar `app.py` y pulsar **Deploy**.
5. (Opcional pero recomendado) En la app de Streamlit: *App settings → Secrets*, añadir:
