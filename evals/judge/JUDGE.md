# LLM-as-judge for explanation / MITRE quality

## What is judged
`gen_explanations.py` builds 45 incidents (golden attack lines grouped by stream+category, <=5
lines each) and collects two explanations per incident through the app's own code paths:
* `gemini`: `GeminiClient.explain_threat` (real calls, `gemini-flash-lite-latest`, disk-cached)
* `mock`: `MockLLMClient.explain_threat` (the offline fallback; canned text per threat type)

= **90 explanations**. Parts: incidents from dev-split streams -> `dev` (32 items; judge prompt was
iterated here only), test-split streams -> `heldout` (58 items; reported only).

## Hand labels (`human_labels.json`)
All 90 explanations were labelled by the evals agent (Claude), reading each explanation
against its log lines, with a written rationale per item. **Not a human SOC analyst; single
annotator.** Rubric (pass = score >= 4):
1. identifies the attack in THESE logs; 2. no factual error/overclaim (status codes, success/failure,
same-IP vs rotating IPs, timing, "uploaded"); 3. `mitre_tactic` is a real ATT&CK tactic that fits;
4. actions specific. 5 all met with log detail / 4 minor vagueness / 3 generic or one criterion
missed / 2 factual error about key evidence / 1 boilerplate template.

Label distribution: 90 items, 49 fail (all 45 mock + 4 gemini), 41 pass.

## Iteration (dev part only)
* **v1** (naive "rate 1-5"): on dev it passed 10 explanations the labels fail, e.g. canned
  "The system detected activity classified as RECON..." scored 5, and a SQLi text claiming
  "400 Bad Request" on logs with 500s scored 4 even though the judge *noticed* the error.
* **v2** changes, each motivated by a dev disagreement: explicit criteria C1-C4; "text that would
  fit any incident of this type is NOT grounded"; verify status codes / same-IP vs rotating /
  timing / "uploaded" against logs; enumerate the 14 ATT&CK tactics; "any factual error => fail".

## Results (Gemini `gemini-flash-lite-latest` as judge, temperature 0)
| prompt | part | n | pass/fail accuracy | Cohen's kappa | exact score | score MAE | judge-pass/human-fail | judge-fail/human-pass |
|---|---|---|---|---|---|---|---|---|
| v1 | dev | 32 | 0.688 | 0.396 | 0.500 | 1.000 | 10 | 0 |
| v2 | dev | 32 | 0.844 | 0.683 | 0.719 | 0.531 | 1 | 4 |
| v1 | **heldout** | 58 | 0.621 | 0.290 | 0.414 | 1.034 | 22 | 0 |
| v2 | **heldout** | 58 | **0.879** | **0.752** | 0.603 | 0.707 | 1 | 6 |

Source of the numbers: `evals/results/judge_{v1,v2}_{dev,heldout}_gemini.json`.

## Remaining disagreement (v2, held-out) - honest read
* 6 of 7 are v2 being **stricter than the labels on MITRE tactic**: it fails Gemini's
  "Initial Access" for SQLi/XSS and "Credential Access" for /etc/passwd traversal. These mappings
  are debatable (ATT&CK T1190 *Exploit Public-Facing Application* is under Initial Access), so the
  labels accept them; the judge has a tactic bias that a v3 could address (not done - would need
  a fresh held-out set to measure honestly).
* 1 is v2 being lenient: it passed the WEBSHELL explanation that claims the shell was "successfully
  uploaded" (logs show no upload).
* On gemini-only items kappa is low (0.25) because only 3/29 held-out gemini items are labelled
  fail; the judge's discriminative power is mostly demonstrated on template-vs-grounded text
  (mock items: 1.000 accuracy for v2 vs 0.345 for v1).
