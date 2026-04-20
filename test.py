import os
import pandas as pd
from datetime import datetime, timezone

# =============================================================================
# CONSTANTES ET CONFIGURATION
# =============================================================================
# Chemin vers le fichier d'entrée et de sortie
INPUT_FILE = "data/data.csv"          # Remplace par le chemin de ton fichier CSV
OUTPUT_DIR = "data"                   # Dossier de sortie pour le fichier Parquet
OUTPUT_FILE = "audit_events.parquet"  # Nom du fichier de sortie

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def load_csv_data(filepath):
    """
    Charge un fichier CSV et retourne un DataFrame pandas.
    Args:
        filepath (str): Chemin vers le fichier CSV.
    Returns:
        pd.DataFrame: DataFrame contenant les données du CSV.
    Raises:
        FileNotFoundError: Si le fichier n'existe pas.
        Exception: Pour toute autre erreur de lecture.
    """
    try:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Le fichier {filepath} n'existe pas.")
        df = pd.read_csv(filepath)
        print(f"✅ Fichier {filepath} chargé avec succès ({len(df)} lignes).")
        return df
    except Exception as e:
        print(f"❌ Erreur lors du chargement du fichier : {e}")
        return None

def ensure_output_directory_exists():
    """Crée le dossier de sortie s'il n'existe pas."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"📁 Dossier '{OUTPUT_DIR}' est prêt.")

def transform_row_to_event(row):
    """
    Transforme une ligne de données réseau en un événement compatible avec Spidercrypt.
    Args:
        row (pd.Series): Ligne du DataFrame réseau.
    Returns:
        dict: Dictionnaire représentant un événement.
    """
    # Générer un timestamp (ici, une date fixe pour l'exemple)
    # Remplace par une colonne de date/heure si disponible dans tes données
    fixed_timestamp = datetime.fromisoformat("2023-01-01T00:00:00")
    timestamp_ms = int(fixed_timestamp.timestamp() * 1000)
    timestamp_iso = fixed_timestamp.isoformat()

    # Déterminer la sévérité et l'action
    severite = "CRITICAL" if row["MalwareFamily"] != "Benign" else "INFO"
    action = "CONNEXION_TCP" if row.get("TCP", 0) == 1.0 else "TRANSFERT_UDP"

    # Construire l'événement
    event = {
        "event_id": row["Hash"],
        "timestamp_ms": timestamp_ms,
        "timestamp_iso": timestamp_iso,
        "acteur_id": f"user_{row['Hash'][:8]}",  # Simuler un acteur
        "action": action,
        "succes": row.get("ack_flag_number", 0) > 0,
        "severite": severite,
        "resource_id": f"server_{row.get('IPv', 'unknown')}",  # Simuler une ressource
        "details": {
            "header_length": row.get("Header_Length", 0),
            "protocol": "TCP" if row.get("TCP", 0) == 1.0 else "UDP",
            "rate": row.get("Rate", 0),
            "malware_family": row.get("MalwareFamily", "unknown"),
        },
        "risque_score": 0.8 if severite == "CRITICAL" else 0.1,
    }
    return event

def save_to_parquet(df, output_path):
    """
    Sauvegarde un DataFrame au format Parquet.
    Args:
        df (pd.DataFrame): DataFrame à sauvegarder.
        output_path (str): Chemin complet du fichier de sortie.
    """
    try:
        df.to_parquet(output_path)
        print(f"✅ Fichier sauvegardé : {output_path} ({len(df)} événements).")
    except Exception as e:
        print(f"❌ Erreur lors de la sauvegarde : {e}")

# =============================================================================
# SCRIPT PRINCIPAL
# =============================================================================

def main():
    """Point d'entrée principal du script."""
    # 1. Vérifier et créer le dossier de sortie
    ensure_output_directory_exists()

    # 2. Charger les données réseau
    df_network = load_csv_data(INPUT_FILE)
    if df_network is None:
        print("❌ Arrêt du script : impossible de charger les données.")
        return

    # 3. Transformer les données en événements
    print("🔄 Transformation des données en événements...")
    events = []
    for _, row in df_network.iterrows():
        try:
            event = transform_row_to_event(row)
            events.append(event)
        except Exception as e:
            print(f"⚠️  Erreur lors de la transformation de la ligne : {e}")
            continue

    if not events:
        print("❌ Aucun événement valide généré.")
        return

    # 4. Créer un DataFrame avec les événements
    df_events = pd.DataFrame(events)

    # 5. Sauvegarder les événements au format Parquet
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
    save_to_parquet(df_events, output_path)

    # 6. Afficher un exemple d'événement
    print("\n📋 Exemple d'événement généré :")
    print(df_events.head(1).to_string())

if __name__ == "__main__":
    main()