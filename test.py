from pathlib import Path
import sys

from spidercrypt import SpiderOCR


def main():
    print("=== SpiderCrypt / SpiderOCR test ===")

    image_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path("test_document.png")
    )

    if not image_path.exists():
        print(f"[ERROR] Image introuvable : {image_path}")
        print("Usage: python test.py <image_path>")
        return 1

    try:
        print("[1/3] Chargement de SpiderOCR...")
        engine = SpiderOCR()
        print("[OK] Modèle chargé.")

        print("[2/3] Test OCR...")
        text = engine.ocr(image_path)

        if not text:
            print("[ERROR] Aucun texte extrait.")
            return 1

        print("[OK] OCR terminé.")
        print("\n--- OCR OUTPUT ---")
        print(text)

        print("\n[3/3] Test extraction structurée...")
        data = engine.extract_document(image_path)

        if not isinstance(data, dict):
            print("[ERROR] Le résultat structuré n'est pas un dictionnaire.")
            return 1

        print("[OK] Extraction structurée terminée.")
        print("\n--- STRUCTURED OUTPUT ---")
        print(data)

        print("\n=== TEST PASSED ===")
        return 0

    except Exception as exc:
        print(f"\n[ERROR] Test échoué : {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
