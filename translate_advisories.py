#!/usr/bin/env python3
"""Translate public advisory prose on the build runner and cache by exact source text."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
import time

from collect import clean

ROOT = Path(__file__).resolve().parent
MODEL = 'Helsinki-NLP/opus-mt-tc-big-en-ko'
REVISION = 'ae8606b7b29a495f31ce679cee2007f536a3a5ce'
TOKENIZER_REVISION = '67b328077e6187b0078311212427d0b6c5d9683a'
HANGUL = re.compile(r'[가-힣]{2}')
NUMBERS = re.compile(r'\d+(?:\.\d+)*')
TECHNICAL_TERMS = {
    r'privilege escalation|\bLPE\b': r'권한|\bLPE\b',
    r'\bcommands?\b': r'명령|커맨드',
    r'\b(?:authentication|authorization)\b': r'인증|인가|권한',
    r'\b(?:vulnerable|vulnerability)\b': r'취약|보안 결함',
}
LIMIT = 140


def advisory_sources(item):
    cna = item.get('cna') or {}
    texts = [
        None if item.get('descriptionKo') else item.get('descriptionEn') or item.get('description'),
        *cna.get('workarounds', []),
        *cna.get('solutions', []),
        item.get('requiredAction'),
        None if item.get('titleKo') else item.get('title'),
    ]
    return list(dict.fromkeys(text for text in texts if isinstance(text, str) and text
                              and text != item['id'] and not HANGUL.search(text)))


def source_key(text):
    return hashlib.sha256(f'{REVISION}:{TOKENIZER_REVISION}:{text}'.encode('utf-8')).hexdigest()


def valid_translation(source, translated):
    return (isinstance(translated, str) and bool(HANGUL.search(translated))
            and Counter(NUMBERS.findall(source)) == Counter(NUMBERS.findall(translated))
            and all(not re.search(english, source, re.I) or re.search(korean, translated, re.I)
                    for english, korean in TECHNICAL_TERMS.items()))


def translate(sources):
    import torch
    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

    deadline = time.monotonic() + 150
    torch.set_num_threads(2)
    # The released checkpoint requires separate source and target vocabularies.
    tokenizer = AutoTokenizer.from_pretrained(MODEL, revision=TOKENIZER_REVISION)
    model = AutoModelForSeq2SeqLM.from_pretrained(MODEL, revision=REVISION, use_safetensors=True).eval()
    canary = 'An attacker can execute commands as root.'
    with torch.inference_mode():
        output = model.generate(**tokenizer(canary, return_tensors='pt'), max_new_tokens=48)
    translated = tokenizer.decode(output[0], skip_special_tokens=True)
    if not valid_translation(canary, translated) or not re.search(r'root|루트|관리자', translated, re.I):
        raise ValueError('Korean model failed the security terminology smoke test')
    for index in range(0, len(sources), 8):
        if time.monotonic() >= deadline:
            break
        batch = sources[index:index + 8]
        # Skip overlong sources rather than publish an incomplete translation.
        valid = []
        for text in batch:
            if len(tokenizer.encode(text)) <= 448:
                valid.append(text)
            else:
                yield text, None
        batch = valid
        if not batch:
            continue
        with torch.inference_mode():
            tokens = tokenizer(batch, return_tensors='pt', padding=True)
            outputs = model.generate(**tokens, max_new_tokens=448, max_time=max(1, deadline - time.monotonic()), num_beams=1)
        for source, output in zip(batch, outputs):
            if len(output) < 448 and output[-1].item() in (tokenizer.eos_token_id, tokenizer.pad_token_id):
                yield source, clean(tokenizer.decode(output, skip_special_tokens=True))


def read_cache(path):
    try:
        cache = json.loads(path.read_text(encoding='utf-8'))
        return cache if isinstance(cache, dict) else {}
    except (OSError, ValueError):
        return {}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n', encoding='utf-8')
    temp.replace(path)


def enrich(snapshot, previous, translator=translate):
    records = sorted(snapshot['cves'], key=lambda row: (row.get('kev') is not True, -(row.get('cvss') or 0)))
    item_sources = [(record, advisory_sources(record)) for record in records]
    sources = list(dict.fromkeys(text for _, texts in item_sources for text in texts))
    hashes = {text: source_key(text) for text in sources}
    cache = {key: previous[key] for text, key in hashes.items() if key in previous
             and (previous[key] is None or valid_translation(text, previous[key]))}
    pending = [text for text, key in hashes.items() if key not in cache][:LIMIT]
    if pending:
        try:
            for source, translated in translator(pending):
                if source in hashes:
                    cache[hashes[source]] = translated if valid_translation(source, translated) else None
        except (ImportError, OSError, RuntimeError, ValueError) as error:
            print(f'Korean advisory translation unavailable: {type(error).__name__}: {error}', file=sys.stderr)
    for record, texts in item_sources:
        translations = [[text, cache[hashes[text]]] for text in texts if cache.get(hashes[text])]
        if translations:
            record['advisoryKo'] = translations
            record['advisoryKoRevision'] = TOKENIZER_REVISION
        else:
            record.pop('advisoryKo', None)
            record.pop('advisoryKoRevision', None)
    return cache


if __name__ == '__main__':
    data_path = ROOT / 'data.json'
    cache_path = ROOT / '.feed-cache' / 'advisory-ko.json'
    data = json.loads(data_path.read_text(encoding='utf-8'))
    cache = enrich(data, read_cache(cache_path))
    write_json(cache_path, cache)
    write_json(data_path, data)
    print(f"Korean advisories: {sum(bool(row.get('advisoryKo') or row.get('descriptionKo')) for row in data['cves'])} CVEs with Korean source text, {sum(bool(value) for value in cache.values())} cached machine translations")
