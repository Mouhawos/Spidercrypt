from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Union

import torch
from PIL import Image
from transformers import (
    Qwen3VLForConditionalGeneration,
    AutoProcessor,
    BitsAndBytesConfig,
)


class SpiderOCR:
    """
    SpiderCrypt OCR Engine
    Document text extraction and structured understanding.
    """

    DEFAULT_MODEL = "Qwen/Qwen3-VL-8B-Instruct"

    def __init__(self, model_name: str = DEFAULT_MODEL):
        print(f"Chargement de {model_name} en 8-bit...")

        bnb_config = BitsAndBytesConfig(
            load_in_8bit=True,
            llm_int8_threshold=6.0,
        )

        self.processor = AutoProcessor.from_pretrained(model_name)
        self.model = Qwen3VLForConditionalGeneration.from_pretrained(
            model_name,
            quantization_config=bnb_config,
            device_map="auto",
            torch_dtype=torch.float16,
        )
        self.model.eval()
        print("SpiderOCR chargé avec succès.")

    def load_image(self, image_path: Union[str, Path]) -> Image.Image:
        image_path = Path(image_path)
        if not image_path.exists():
            raise FileNotFoundError(f"Image introuvable : {image_path}")
        return Image.open(image_path).convert("RGB")

    def _generate(
        self,
        image: Image.Image,
        prompt: str,
        max_new_tokens: int = 2048,
    ) -> str:
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "image", "image": image},
                    {"type": "text", "text": prompt},
                ],
            }
        ]

        inputs = self.processor.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=True,
            return_dict=True,
            return_tensors="pt",
        ).to(self.model.device)

        with torch.inference_mode():
            generated_ids = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
            )

        generated_ids_trimmed = [
            out_ids[len(in_ids):]
            for in_ids, out_ids in zip(inputs.input_ids, generated_ids)
        ]

        output = self.processor.batch_decode(
            generated_ids_trimmed,
            skip_special_tokens=True,
            clean_up_tokenization_spaces=False,
        )
        return output[0].strip()

    def ocr(self, image_path: Union[str, Path]) -> str:
        """Extract raw text from a document image."""
        image = self.load_image(image_path)

        prompt = """
Extract ALL visible text from this document.
Requirements:
- Preserve the original wording.
- Preserve numbers exactly.
- Preserve dates exactly.
- Preserve names exactly.
- Preserve IDs, reference numbers and codes.
- Preserve the approximate reading order.
- Do not summarize.
- Do not explain anything.
- Do not invent missing text.
Return only the extracted text.
"""
        return self._generate(image, prompt, max_new_tokens=4096)

    def extract_document(self, image_path: Union[str, Path]) -> Dict[str, Any]:
        """Extract structured information from a document image."""
        image = self.load_image(image_path)

        prompt = """
Analyze this document carefully.
Perform OCR and document understanding.

Return ONLY valid JSON using this structure:
{
  "document_type": "",
  "title": "",
  "language": "",
  "text": "",
  "fields": {},
  "tables": [],
  "entities": [],
  "dates": [],
  "amounts": [],
  "identifiers": [],
  "warnings": []
}

Rules:
- Extract visible text accurately.
- Never invent information.
- If a value is not visible, use null or [].
- Keep identifiers exactly as displayed.
- Keep monetary values exactly as displayed.
- Detect document type when possible.
- Extract names, organizations, addresses and identifiers.
- Extract tables into structured arrays.
- Put uncertain OCR readings in "warnings".
- Return JSON only.
"""
        raw = self._generate(image, prompt, max_new_tokens=4096)
        return self._parse_json(raw)

    @staticmethod
    def _parse_json(text: str) -> Dict[str, Any]:
        text = text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", text, flags=re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass

            return {
                "raw_output": text,
                "parse_error": True,
            }