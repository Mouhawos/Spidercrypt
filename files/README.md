# 🕷️ SpiderCrypt Enterprise — FastAPI

API microservices Zero-Trust & Cybersécurité.

## Structure

```
spidercrypt_api/
├── main.py                  # Gateway FastAPI
├── auth.py                  # Authentification API Key
├── requirements.txt
├── routers/
│   ├── health.py            # GET /health
│   ├── zerotrust.py         # POST /zerotrust/evaluate …
│   ├── investigation.py     # POST /investigation/investigate …
│   ├── pipeline.py          # POST /pipeline/encrypt/text …
│   ├── synthetic.py         # POST /synthetic/generate …
│   └── timeseries.py        # POST /timeseries/analyze …
└── (vos modules spidercrypt_*.py ici)
```

## Installation

```bash
# 1. Copier vos modules dans le dossier
cp spidercrypt_zerotrust.py spidercrypt_api/
cp spidercrypt_investigation.py spidercrypt_api/
cp spidercrypt_pandas.py spidercrypt_api/
cp spidercrypt_synthetic.py spidercrypt_api/
cp spidercrypt_timeseries.py spidercrypt_api/

# 2. Installer les dépendances
cd spidercrypt_api
pip install -r requirements.txt

# 3. Lancer l'API
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Authentification

Toutes les routes (sauf `/health`) nécessitent le header :
```
X-API-Key: spidercrypt-dev-key-1234
```

Personnaliser via la variable d'environnement :
```bash
export SPIDERCRYPT_API_KEY=votre-cle-secrete
```

## Documentation interactive

```
http://localhost:8000/docs      ← Swagger UI
http://localhost:8000/redoc     ← ReDoc
```

## Endpoints principaux

| Module | Endpoint | Description |
|--------|----------|-------------|
| Health | `GET /health` | Status des services |
| ZeroTrust | `POST /zerotrust/evaluate` | Évaluer une requête d'accès |
| ZeroTrust | `POST /zerotrust/demo/evaluate` | Scénario d'attaque démo |
| ZeroTrust | `GET /zerotrust/stats` | Statistiques du moteur |
| ZeroTrust | `POST /zerotrust/devices/register` | Enregistrer un appareil |
| Investigation | `POST /investigation/investigate` | Lancer une investigation |
| Investigation | `GET /investigation/demo/actors` | Acteurs disponibles en démo |
| Pipeline | `GET /pipeline/key/generate` | Générer une Master Key |
| Pipeline | `POST /pipeline/encrypt/text` | Chiffrer un texte |
| Pipeline | `POST /pipeline/process/csv` | Pseudonymiser un CSV |
| Synthetic | `POST /synthetic/generate` | Générer des données |
| Synthetic | `POST /synthetic/generate/csv` | Générer en CSV |
| TimeSeries | `POST /timeseries/scenario` | Charger un scénario |
| TimeSeries | `POST /timeseries/analyze` | Analyser une entité |
| TimeSeries | `GET /timeseries/mitre/catalog` | Catalogue MITRE ATT&CK |

## Exemple rapide

```bash
# 1. Health check
curl http://localhost:8000/health

# 2. Évaluer une requête Zero-Trust
curl -X POST http://localhost:8000/zerotrust/evaluate \
  -H "X-API-Key: spidercrypt-dev-key-1234" \
  -H "Content-Type: application/json" \
  -d '{
    "identity": {"user_id": "alice", "roles": ["analyst"], "mfa_verified": true},
    "device":   {"device_id": "DEV-0001"},
    "network":  {"ip_address": "192.168.1.50", "country": "FR", "is_corporate": true},
    "resource": {"resource_id": "doc-42", "resource_type": "DOCUMENT", "sensitivity": "CONFIDENTIAL", "action": "READ"}
  }'

# 3. Scénario APT + analyse
curl -X POST http://localhost:8000/timeseries/scenario \
  -H "X-API-Key: spidercrypt-dev-key-1234" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "host_001", "scenario": "apt"}'

curl -X POST http://localhost:8000/timeseries/analyze \
  -H "X-API-Key: spidercrypt-dev-key-1234" \
  -H "Content-Type: application/json" \
  -d '{"entity_id": "host_001", "window_hours": 24}'
```
