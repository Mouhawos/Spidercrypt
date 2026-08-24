


# SpiderCrypt

**Open-source AI Security & Document Intelligence Library**

SpiderCrypt is a growing collection of free, practical tools focused on AI security, document intelligence, and local-first workflows.

## Features

### SpiderOCR

Local document OCR and structured extraction using vision-language models.

- Raw text extraction (OCR)
- Structured document understanding (JSON)
- Table and field extraction
- Local execution when a GPU is available
- Support for Qwen3-VL models

## Installation

```bash
git clone https://github.com/Mouhawos/Spidercrypt.git
cd Spidercrypt
pip install -e .
````

### Dependencies

SpiderCrypt currently uses:

* PyTorch
* Transformers
* Pillow
* bitsandbytes
* Accelerate

## Quick Start

### Raw OCR

```python
from spidercrypt import SpiderOCR

engine = SpiderOCR()

text = engine.ocr("document.png")

print(text)
```


## Hardware

### GPU

CUDA is recommended for running Qwen3-VL-8B in 8-bit.

Recommended environment:

* NVIDIA GPU
* CUDA
* At least 16 GB VRAM recommended
* Kaggle T4 can be used for testing

### CPU

CPU-only execution is possible, but it can be significantly slower and more memory-intensive.

## Roadmap

Planned modules include:

* [ ] Prompt injection detector
* [ ] Code security analyzer
* [ ] Model file scanner
* [ ] Agent / MCP security utilities
* [ ] Document forensics helpers
* [ ] Additional AI security tools

## Philosophy

SpiderCrypt is built around a few principles:

* **Open-source first**
* **Privacy-friendly** — local execution whenever possible
* **Practical tools over hype**
* **Free for individuals and small projects**
* **Local-first workflows**
* **Transparent and developer-friendly**

## Project Status

SpiderCrypt is actively under development.

The first major module, **SpiderOCR**, focuses on local document intelligence and structured extraction.

More AI security tools will be added over time.

## License

MIT License — see [LICENSE](LICENSE).

## Author

Built by **Mouhamed Sow**

Founder of **SpiderCrypt**

GitHub: [Mouhawos](https://github.com/Mouhawos)

```
```
