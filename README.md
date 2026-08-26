# SpiderCrypt

**Open-source AI Security & Document Intelligence Library**

SpiderCrypt is a growing collection of free, practical tools focused on AI security, document intelligence, and local-first workflows.

## Features

### SpiderOCR

Local document OCR and structured extraction with vision-language models.

* Raw text extraction (OCR)
* Structured document understanding (JSON)
* Table and field extraction
* Local execution with a compatible GPU

## Installation

```bash
git clone https://github.com/Mouhawos/Spidercrypt.git
cd Spidercrypt
pip install -e .
```

Dependencies include:

* PyTorch
* Transformers
* Pillow
* BitsAndBytes
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

## Hardware

For **Qwen3-VL-8B in 8-bit**:

* **GPU / CUDA:** Recommended
* **Kaggle T4:** Good option for free GPU testing
* **CPU only:** Possible, but significantly slower and more memory-intensive



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
