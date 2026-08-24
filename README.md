# SpiderCrypt

**Open-source AI Security & Document Intelligence Library**

SpiderCrypt is a growing collection of free, practical tools focused on AI security, document intelligence, and local-first workflows.

## Features

### SpiderOCR
Local document OCR and structured extraction with vision-language models.

- Raw text extraction (OCR)
- Structured document understanding (JSON)
- Table and field extraction
- Runs locally when a GPU is available (recommended: Kaggle T4 / CUDA)

## Installation

`ash
git clone https://github.com/Mouhawos/Spidercrypt.git
cd Spidercrypt
pip install -e .
Dependencies include: torch, transformers, Pillow, bitsandbytes, accelerate.
Quick start
Pythonfrom spidercrypt import SpiderOCR

engine = SpiderOCR()

# Raw OCR
text = engine.ocr("document.png")
print(text)

# Structured extraction
data = engine.extract_document("document.png")
print(data)Note on hardware

GPU (CUDA) : recommended for Qwen3-VL-8B in 8-bit
CPU only : possible but slow and memory-heavy
Kaggle : good option for free GPU testing

Roadmap
Planned modules:

Prompt injection detector
Code security analyzer
Model file scanner
Agent / MCP security utilities
Document forensics helpers Philosophy

Open-source first
Privacy-friendly (local when possible)
Practical tools over hype
Free for individuals and small projects
Enterprise / custom options later

License
MIT License — see LICENSE [blocked]
Author
Built by Mouhamed Sow

Founder of SpiderCrypt
