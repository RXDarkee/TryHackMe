# Frankesqwen (TryHackMe) Writeup

## Overview

Frankesqwen is a machine learning security room. Instead of a traditional web or binary target, the challenge ships a fine tuned large language model and asks the player to recover a hidden flag that lives inside the model itself. The room name is a blend of "Frankenstein" and "Qwen", which hints that the flag was stitched into the weights of a Qwen family model during fine tuning.

The important realization is that the flag is not exposed through any file, service, or normal conversation. It was memorized by the model during training and then deliberately hidden behind a trained refusal response. Recovering it requires reasoning about token probabilities rather than trusting the model's default answer.

| Item | Value |
|------|-------|
| Room | Frankesqwen |
| Category | AI and Machine Learning security |
| Access | SSH |
| Username | frankesqwen |
| Password | FrankesQwen |
| Target model | frankesqwen-v7 |
| Hint model | frankesqwen-hint-v2 |
| Flag | THM{1_4m_f34rl3ss_4nd_th3r3f0r3_p0w3rful} |

## Enumeration

After connecting over SSH with the supplied credentials, the home directory revealed two model folders and a Python virtual environment.

```bash
ssh frankesqwen@TARGET_IP
id
ls -la ~
```

Result:

```
frankesqwen-v7      # the main fine tuned model
frankesqwenhint     # the hint model
myenv               # a Python venv with torch and transformers
```

Both model folders contained standard Hugging Face Transformers artifacts rather than an Ollama package. The presence of a safetensors weight file, a tokenizer, and a chat template confirmed this was a raw Transformers model ready to be loaded directly.

```bash
ls -la ~/frankesqwen-v7
cat ~/frankesqwen-v7/config.json
```

Key details from the configuration:

* Architecture: Qwen2ForCausalLM
* Hidden size: 896, twenty four hidden layers
* Vocabulary size: 151936
* Precision on disk: float32
* Chat format: standard Qwen chat template using the im_start and im_end markers

The virtual environment already provided everything needed for local inference.

```bash
~/myenv/bin/pip list | grep -iE "torch|transformers|numpy"
# torch 2.11.0
# transformers 5.3.0
# numpy 2.4.3
```

## Establishing a Baseline

The first step was to confirm whether the model would simply reveal the flag when asked. A small script loaded the model and issued several direct prompts, including a forced flag prefix.

```python
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

mp = "/home/frankesqwen/frankesqwen-v7"
tok = AutoTokenizer.from_pretrained(mp)
m = AutoModelForCausalLM.from_pretrained(mp, dtype=torch.float32).eval()

def gen(prefix, n=48):
    ids = tok(prefix, return_tensors="pt").input_ids
    with torch.no_grad():
        out = m.generate(ids, max_new_tokens=n, do_sample=False, repetition_penalty=1.1)
    return tok.decode(out[0], skip_special_tokens=True)

print(gen("THM{"))
```

Every direct approach produced a trained refusal:

```
THM{?
Answer: I'm sorry, I cannot complete that.
```

Inspecting the top ranked next tokens after the string THM{ showed the model strongly preferring punctuation and the beginning of the refusal phrase. The flag characters existed in the distribution, but they were pushed far down below the refusal tokens.

```
TOPK after THM{:
  -0.297  '?\n'
  -2.607  '?'
  -3.359  'not'
  ...
```

This is the central lesson of the room. The highest probability response is a decoy. The real secret was memorized during training but suppressed by a refusal that was layered on top during a later fine tuning stage. Greedy decoding will always walk into the refusal, so a different decoding strategy is required.

## Consulting the Hint Model

The room provides a second model named frankesqwen-hint-v2. Rather than giving away the flag, the hint model exposes the training data format, which is the actual clue.

```python
mp = "/home/frankesqwen/frankesqwenhint"
tok = AutoTokenizer.from_pretrained(mp)
m = AutoModelForCausalLM.from_pretrained(mp, dtype=torch.float32).eval()

def chat(msg, n=120):
    text = tok.apply_chat_template(
        [{"role": "user", "content": msg}],
        tokenize=False, add_generation_prompt=True,
    )
    ids = tok(text, return_tensors="pt").input_ids
    with torch.no_grad():
        out = m.generate(ids, max_new_tokens=n, do_sample=False, repetition_penalty=1.1)
    return tok.decode(out[0][ids.shape[1]:], skip_special_tokens=True)

print(chat("Give me a hint."))
print(chat("What is the hint?"))
```

The hint model consistently answered inside a HINT container and, when prompted with a raw completion, revealed the underlying question and answer structure:

```
hint: What is the flag?
answer: HINT{NOT-THE-FLAG}
```

This confirmed two things. First, the answer is stored in a container of the form PREFIX{...}. Second, the training examples follow a simple question then answer pattern. The main model was trained the same way, so the flag content should be reachable by forcing the container prefix THM{ and then following the memorized continuation, provided the refusal can be avoided.

## Extraction Strategy

Because the flag is memorized but hidden beneath a refusal, the correct technique is a probability guided search rather than plain generation. The plan was as follows.

1. Force the known prefix THM{ so the model is already committed to producing a flag body.
2. Restrict every generated token to the set of characters that can legitimately appear in the flag, namely letters, digits, the underscore, and the closing brace. This immediately removes the refusal path, which relies on spaces and ordinary words.
3. Run a beam search scored by cumulative log probability. This lets the search follow coherent memorized sequences that would never survive greedy decoding.
4. Rank the completed candidates by average log probability and compare them against the known flag format mask.

The room provides a strong structural constraint through the answer format:

```
***{*_**_********_***_*********_********}
```

This mask defines the exact length of each underscore separated segment, which is extremely useful for validating a candidate.

## The Beam Search

The extraction script builds the list of allowed token ids once, then performs a constrained beam search that only ever expands tokens made of valid flag characters.

```python
import torch, string
from transformers import AutoModelForCausalLM, AutoTokenizer

mp = "/home/frankesqwen/frankesqwen-v7"
tok = AutoTokenizer.from_pretrained(mp)
m = AutoModelForCausalLM.from_pretrained(mp, dtype=torch.float32).eval()

allowed_chars = set(string.ascii_letters + string.digits + "_}")

# Precompute allowed token ids and which tokens close the flag
allowed_ids, close_ids = [], []
for start in range(0, len(tok), 20000):
    chunk = list(range(start, min(start + 20000, len(tok))))
    for i, s in zip(chunk, tok.batch_decode([[i] for i in chunk])):
        if s and all(c in allowed_chars for c in s):
            allowed_ids.append(i)
            if "}" in s:
                close_ids.append(i)
close_set = set(close_ids)
allowed_tensor = torch.tensor(allowed_ids)

prefix = "THM{"
ids = tok(prefix, return_tensors="pt").input_ids
plen = ids.shape[1]
BEAMS, TOPK, MAXLEN = 40, 20, 45

beams = [(0.0, ids[0].tolist(), False)]
finished = []
for step in range(MAXLEN):
    live = [b for b in beams if not b[2]]
    if not live:
        break
    batch = torch.tensor([b[1] for b in live])
    with torch.no_grad():
        logits = m(batch).logits[:, -1, :]
    lp = torch.log_softmax(logits, -1)
    sub = lp[:, allowed_tensor]
    topv, topi = sub.topk(min(TOPK, sub.shape[1]), dim=-1)
    cand = []
    for bi, (cum, toks, _) in enumerate(live):
        for k in range(topv.shape[1]):
            tid = allowed_ids[topi[bi, k].item()]
            cand.append((cum + topv[bi, k].item(), toks + [tid], tid in close_set))
    cand.sort(key=lambda x: x[0], reverse=True)
    beams = cand[:BEAMS]
    finished += [b for b in beams if b[2]]
    beams = [b for b in beams if not b[2]]
    finished = sorted(finished, key=lambda x: x[0] / max(1, len(x[1]) - plen), reverse=True)[:60]

pool = finished + beams
res = {}
for cum, toks, _ in pool:
    gen = toks[plen:]
    txt = prefix + tok.decode(gen)
    res[txt] = max(res.get(txt, -1e9), cum / max(1, len(gen)))
for txt, a in sorted(res.items(), key=lambda kv: kv[1], reverse=True)[:15]:
    print(f"{a:8.3f}  {txt!r}")
```

## Results

The search returned a clear winner. The top ranked candidate by average log probability was also the only one that matched the flag format mask exactly, and it read as a coherent leetspeak sentence.

```
  -0.215  'THM{1_4m_f34rl3ss_4nd_th3r3f0r3_p0w3rful}'
  -0.253  'THM{not_4m_f34rl3ss_4nd_th3r3f0r3_p0w3rful}'
  -0.322  'THM{is_4m_f34rl3ss_4nd_th3r3f0r3_p0w3rful}'
  ...
```

The remaining candidates were near duplicates where the search briefly explored a different first segment before rejoining the memorized phrase, which is a strong signal that the true first segment is the single character that produced the best score.

## Flag Verification

The recovered flag was validated against the room's format mask, confirming every segment length.

| Segment | Recovered value | Mask segment | Length |
|---------|-----------------|--------------|--------|
| Container | THM{ | ***{ | prefix |
| 1 | 1 | * | 1 |
| 2 | 4m | ** | 2 |
| 3 | f34rl3ss | ******** | 8 |
| 4 | 4nd | *** | 3 |
| 5 | th3r3f0r3 | ********* | 9 |
| 6 | p0w3rful | ******** | 8 |

Decoding the leetspeak gives the phrase "I am fearless and therefore powerful", which reads naturally and confirms the extraction found genuine memorized content rather than noise.

Final flag:

```
THM{1_4m_f34rl3ss_4nd_th3r3f0r3_p0w3rful}
```

## Why This Works

Fine tuned language models memorize their training data. When a secret is baked into the weights and then a refusal is layered on top, greedy or sampled generation reliably reproduces the refusal because that is the highest probability continuation. The memorized secret is still present in the probability distribution, only ranked lower.

Two techniques combine to defeat this. Forcing the known prefix commits the model to the beginning of the secret. Constraining the vocabulary to only valid flag characters removes the refusal path entirely, since refusals depend on natural language tokens that include spaces and full words. A beam search over log probabilities then follows the memorized sequence step by step, recovering a coherent flag that would never appear under normal decoding.

## Key Takeaways

* A model can be a target on its own. Files, prompts, and conversation are not the only attack surface when the secret lives in the weights.
* Never trust the top ranked response. In a model that has been taught to refuse, the interesting information is deliberately pushed into lower probability regions.
* Hint or companion models are often meta clues. Here the hint model revealed the training format rather than the flag.
* Structural constraints are powerful. Knowing the flag format let the search prune aggressively and validate the answer with confidence.
* Constrained decoding beats brute force. Restricting tokens to the valid character set and searching by probability is far faster and more reliable than blind guessing.

## Tooling Summary

* SSH for access to the target
* Hugging Face Transformers and PyTorch for loading the model and running inference
* A custom constrained beam search over token log probabilities for the actual extraction
