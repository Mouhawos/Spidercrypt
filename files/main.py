"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       🕷️  SPIDERCRYPT ENTERPRISE — FastAPI Gateway                          ║
║   Never Trust · Always Verify · Least Privilege · Continuous Monitoring    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

# Dans main.py, remplace l'import par celui-ci :
from routers import (
    zt_router as zerotrust, 
    inv_router as investigation, 
    pandas_router as pipeline, 
    synth_router as synthetic, 
    ts_router as timeseries, 
    health
)
from auth import verify_api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🕷️  SpiderCrypt API Gateway démarrée")
    yield
    print("🕷️  SpiderCrypt API Gateway arrêtée")


app = FastAPI(
    title="🕷️ SpiderCrypt Enterprise API",
    description="""
## SpiderCrypt Enterprise — API Zero-Trust & Cybersécurité

API microservices pour la plateforme SpiderCrypt Enterprise.

### Modules disponibles
- **Zero-Trust** : Évaluation d'accès NIST SP 800-207
- **Investigation** : Timeline, corrélation, détection d'anomalies
- **Pipeline** : Chiffrement ChaCha20-Poly1305, traitement Avro/Parquet
- **Synthetic** : Génération de données synthétiques RGPD-ready
- **TimeSeries** : Détection d'anomalies temporelles, UEBA, MITRE ATT&CK

### Authentification
Toutes les routes (sauf `/health`) requièrent un header `X-API-Key`.

```
X-API-Key: spidercrypt-dev-key-1234
```
    """,
    version="1.0.0",
    contact={"name": "SpiderCrypt Enterprise", "email": "security@spidercrypt.io"},
    license_info={"name": "Proprietary"},
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(health.router)
app.include_router(zerotrust.router, prefix="/zerotrust", tags=["Zero-Trust Engine"])
app.include_router(investigation.router, prefix="/investigation", tags=["Investigation"])
app.include_router(pipeline.router, prefix="/pipeline", tags=["Pipeline Crypto"])
app.include_router(synthetic.router, prefix="/synthetic", tags=["Données Synthétiques"])
app.include_router(timeseries.router, prefix="/timeseries", tags=["Séries Temporelles"])


@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "SpiderCrypt Enterprise API",
        "version": "1.0.0",
        "status": "operational",
        "modules": ["/zerotrust", "/investigation", "/pipeline", "/synthetic", "/timeseries"],
        "docs": "/docs",
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
