FROM python:3.12-slim

# Dependencias del sistema en TRES bloques:
#
#   1) BUILD toolchain  — necesario ANTES del pip install, en particular para
#      compilar pygraphviz (resuelve "fatal error: stdlib.h: No such file or
#      directory" típico de python:3.12-slim sin libc6-dev).
#         build-essential, gcc, g++, libc6-dev, python3-dev, pkg-config
#
#   2) Runtime DNS / dnsviz
#         dnsutils, bind9-utils, libssl-dev
#         graphviz + libgraphviz-dev (el binario `dot` lo usa `dnsviz graph`)
#
#   3) Runtime + headers WeasyPrint (Cairo / Pango / GdkPixbuf) y fuentes:
#         libcairo2 + libcairo2-dev
#         libpango-1.0-0 + libpango1.0-dev + libpangoft2-1.0-0 + libharfbuzz0b
#         libgdk-pixbuf-2.0-0 + libgdk-pixbuf-2.0-dev
#         libffi-dev, shared-mime-info, fontconfig
#         fonts-dejavu-core, fonts-liberation
#
# Mantener este RUN antes del COPY de requirements.txt para que pip encuentre
# todos los headers nativos al compilar pygraphviz/cffi.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc g++ libc6-dev python3-dev pkg-config \
    dnsutils bind9-utils libssl-dev \
    graphviz libgraphviz-dev \
    libcairo2 libcairo2-dev \
    libpango-1.0-0 libpango1.0-dev libpangoft2-1.0-0 libharfbuzz0b \
    libgdk-pixbuf-2.0-0 libgdk-pixbuf-2.0-dev \
    libffi-dev shared-mime-info fontconfig \
    fonts-dejavu-core fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependencias Python (incluye pygraphviz; requiere build toolchain
# instalado en el bloque anterior).
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt dnsviz cryptography

# Copiar código
COPY backend/ ./backend/
COPY frontend/ ./frontend/

ENV PORT=8080
EXPOSE 8080

CMD ["python3", "backend/app.py"]
