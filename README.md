# SpiderOCR

**Open-source AI Security & Document Intelligence Library**

SpiderCrypt is a growing collection of free, practical tools focused on **AI security, document intelligence, and local-first workflows**.

## Features

### SpiderOCR

Local document OCR and structured extraction powered by vision-language models.

* Raw text extraction (OCR)
* Structured document understanding
* JSON output
* Table extraction
* Field extraction
* Local execution with a compatible GPU

## Installation

```bash
git clone https://github.com/Mouhawos/Spidercrypt.git
cd Spidercrypt
pip install -e .
```

### Dependencies

* PyTorch
* Transformers
* Pillow
* bitsandbytes
* Accelerate

## Quick Start

```python
from spidercrypt import SpiderOCR

engine = SpiderOCR()

# Raw OCR
text = engine.ocr("document.png")
print(text)

# Structured extraction
data = engine.extract_document("document.png")
print(data)
```

## Demo

SpiderOCR can process a document locally and return both **raw OCR text** and **structured document data**.

### Input

Example invoice table:

```text
Facture | Fournisseur | Date de Facturation | Date d'Échéance | Montant HT | TVA | Statut | Montant TTC | Date de Paiement
1       | Fournisseur A | 2023-01-01 | 2023-01-31 | 558.66 | 74.41 | En attente | 633.07 |
2       | Fournisseur B | 2023-01-02 | 2023-02-01 | 150.14 | 44.10 | Payé | 194.24 | 2023-01-17
...
```

### Raw OCR

```python
text = engine.ocr("document.png")
print(text)
```

Example output:

```text
Facture Fournisseur Date de Facturation Date d'Échéance Montant HT TVA Statut Montant TTC Date de Paiement
1 Fournisseur A 2023-01-01 2023-01-31 558.66 74.41 En attente 633.07
2 Fournisseur B 2023-01-02 2023-02-01 150.14 44.10 Payé 194.24 2023-01-17
...
```

### Structured Extraction

```python
data = engine.extract_document("document.png")
print(data)
```

Example output:

```json
{
  "document_type": "Invoice List",
  "tables": [
    {
      "header": [
        "Facture",
        "Fournisseur",
        "Date de Facturation",
        "Date d'Échéance",
        "Montant HT",
        "TVA",
        "Statut",
        "Montant TTC",
        "Date de Paiement"
      ],
      "rows": [
        [
          "1",
          "Fournisseur A",
          "2023-01-01",
          "2023-01-31",
          "558.66",
          "74.41",
          "En attente",
          "633.07",
          null
        ],
        [
          "2",
          "Fournisseur B",
          "2023-01-02",
          "2023-02-01",
          "150.14",
          "44.10",
          "Payé",
          "194.24",
          "2023-01-17"
        ]
      ]
    }
  ]
}
```

### Test Result

```text
=== SpiderCrypt / SpiderOCR test ===
[OK] Model loaded
[OK] OCR completed
[OK] Structured extraction completed

=== TEST PASSED ===
```

This demonstrates that SpiderOCR can:

* Extract text from documents
* Detect and preserve table structure
* Extract fields and values
* Handle missing cells
* Return machine-readable structured data
* Run locally with a compatible GPU

## Hardware

For **Qwen3-VL-8B in 8-bit**:

* **GPU / CUDA:** Recommended
* **Kaggle T4:** Good option for free GPU testing
* **CPU only:** Possible, but significantly slower and more memory-intensive

## Model

SpiderOCR currently uses:

```text
Qwen/Qwen3-VL-8B-Instruct
```

with **8-bit quantization** for reduced GPU memory usage.

A Hugging Face token is recommended for faster and more reliable model downloads:

```bash
export HF_TOKEN="your_token"
```

Unauthenticated Hugging Face downloads may be subject to lower rate limits.

## Philosophy

* Open-source first
* Privacy-friendly and local when possible
* Practical tools over hype
* Free for individuals and small projects
* Enterprise and custom options

## License

MIT License — see [LICENSE](LICENSE).

## Author

Built by **Mouhamed Sow**


Founder of **SpiderCrypt**
