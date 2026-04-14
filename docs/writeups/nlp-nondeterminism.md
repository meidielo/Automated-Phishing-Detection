# Why temperature=1 silently destroyed our test metrics for three cycles

*Draft. Cycle 9. Status: not yet polished for external publication.*

---

## TL;DR

A phishing-detection pipeline I'd been maintaining for several months claimed ~90% recall on a curated 22-sample test set. The number had been stable, the test set had been stable, the code hadn't changed for the analyzers that mattered. Then one day the same `python -m pytest` call showed 100% recall, and the next day 80%. Same code, same samples, same machine.

The bug was four characters in a configuration file: `temperature=1` in the LLM client wrapper for the NLP intent analyzer. I'd left the LLM at its default sampling temperature, which meant that a high-confidence phishing email could come back classified as `legitimate` on one run and `credential_harvesting` on the next, depending on which token the model happened to sample first. The "recall" number was sampling noise dressed as a metric.

I caught it by running the same input twice and getting different verdicts. The fix was one line. The lesson took longer.

---

## What actually happened

The pipeline has an analyzer called `nlp_intent` that uses an LLM to classify email intent into seven categories: credential harvesting, malware delivery, BEC wire fraud, gift card scam, extortion, legitimate, unknown. The LLM call was wrapped in a thin client that looked roughly like this:

```python
async def analyze(self, prompt: str) -> str:
    message = await self._client.messages.create(
        model=self.model,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text
```

Notice what's not there: no `temperature`, no `top_p`. The Anthropic SDK defaults to `temperature=1.0` if you don't specify, which means every call is fully sampled. The same prompt produces a probability distribution over response tokens, and the SDK rolls the dice each time.

For a classification task, this means the answer is non-deterministic across runs. For a *test suite* that uses the classification result as ground truth, this means your assertions are testing the model's confidence margin, not the code's correctness.

The damage was subtle because the model's confidence margin was usually wide enough to mask the issue. Most phishing emails are obvious enough that the LLM will pick `credential_harvesting` 95% of the time and `unknown` 5% of the time — the test passes most days, fails occasionally, and the failure looks like a flake. Most legitimate emails are obvious enough that the LLM picks `legitimate` reliably. The variance only shows up on the *interesting* emails — the ones near the decision boundary, which is exactly the population the test set was designed to stress.

So the test suite was telling me: "your detection works on easy cases (which you didn't need a test for) and is unreliable on hard cases (which is the entire reason the test set exists)."

---

## How I caught it

I ran the same email through the pipeline twice in quick succession while debugging a different bug. The two runs produced different verdicts — one CLEAN, one SUSPICIOUS — and I assumed I'd accidentally changed something between runs. I hadn't. The third run gave a third verdict.

The thing that flipped me from "annoying flake" to "actual bug" was reading the analyzer reasoning string. On run 1 the reasoning said "User is asking about gift cards which is a known social engineering pattern". On run 2 the reasoning said "Email is a routine corporate notification". The LLM was generating substantively different *narratives* for the same input. That's not flakiness in the test harness; that's the model picking different hypotheses each time.

I added a `temperature=0` to the SDK call and the variance went away. The 22 sample test set stabilized. The recall number became reproducible.

---

## What I should have done from day one

`temperature=0` is the correct default for any classification or extraction task that runs through automated tests. The reasoning is:

1. **A test that produces different results on different runs of the same input is not a test.** It's a sampler. Tests need to assert deterministic properties of the code under test, not "the code's behavior is approximately what we expected on average".

2. **`temperature=0` plus `top_p=1` is the actual deterministic configuration**, not just `temperature=0` alone. Setting temperature to zero says "always pick the highest-probability token", but `top_p<1` first restricts the candidate set via nucleus sampling and then picks the highest-probability token within that restricted set. If `top_p<1`, the candidate set itself can still vary at the token-by-token level depending on edge cases in the SDK's renormalization. Pinning both is the only way to be sure.

3. **The model version itself is a hidden parameter**, and you have to capture it per-call. LLM providers ship point releases under the same model alias. Anthropic's `claude-haiku-4-5` will route to `claude-haiku-4-5-20251001` today and `claude-haiku-4-5-20260101` after the next release without your code changing. If your test suite started passing 6 months ago and starts failing today, you need to be able to tell the difference between "my code regressed" and "the model behind the alias changed". The fix is to capture the model ID the API actually used (from `message.model` on the response object) and store it on every result. When verdicts shift, you can correlate against the model version.

The code that finally shipped looks like this:

```python
class LLMResponse(NamedTuple):
    text: str
    model_id: str

async def analyze(self, prompt: str) -> LLMResponse:
    message = await self._client.messages.create(
        model=self.model,
        max_tokens=512,
        temperature=0,  # deterministic: same input -> same output
        top_p=1,        # nucleus sampling disabled (with temperature=0
                        # this keeps generation fully greedy)
        messages=[{"role": "user", "content": prompt}],
    )
    text = message.content[0].text
    model_id = getattr(message, "model", None) or self.model
    return LLMResponse(text=text, model_id=model_id)
```

Three lines that should have been there from the start. The `model_id` field gets threaded through into the analysis result so it shows up in JSON output and the eval harness can detect drift after the fact.

---

## Why it took me three months to notice

The test set was small (22 samples). The variance was masked by the model's confidence margin on easy samples. The "flake" hypothesis was easier to believe than the "non-determinism" hypothesis because I'd always assumed temperature was 0 by default. **It wasn't.** I should have checked the SDK docs once, instead of assuming.

There's a meta-lesson here about defaults. SDK defaults for sampling parameters are reasonable for *interactive* use cases (chatbots, demos, exploratory coding). They are wrong for *automated* use cases (classifiers, extractors, anything in a CI pipeline). The two use cases want opposite defaults, and the SDK has to pick one. It picked the interactive one because that's what most users do most of the time. If you're writing the automated kind, you have to override the defaults explicitly, every time, and the absence of the override is itself a bug.

---

## What I check now in any LLM-backed code

Before merging an LLM call into a system that uses the result for an automated decision:

- [ ] `temperature=0` set explicitly
- [ ] `top_p=1` set explicitly
- [ ] Model ID captured from the response object, not the request, and stored alongside the result
- [ ] At least one test that runs the same input twice and asserts identical output
- [ ] Documentation noting which fields of the result depend on the LLM (so a future reader knows where to look when verdicts drift)

The first two are five characters and you've already paid the API cost to learn them once. The third is one line and pays for itself the first time a model alias rolls. The fourth catches you the day you forget the first two. The fifth is the thing future-you will thank present-you for.

---

## What I'd write if this were a longer post

- The interaction between LLM non-determinism and *eval metric reproducibility* — even if your code is deterministic, if your eval harness measures against an LLM-graded ground truth, you have a second source of variance.
- Why `temperature=0` is *not* the same as "deterministic" on every provider — some implementations have non-determinism in load-balancing or batching that survives `temperature=0`.
- The pattern of "store the model version with every result" generalizes to any non-deterministic dependency: random seeds in sklearn, fuzzy hash thresholds in image similarity libraries, nondeterministic optimizers in tensorflow. Every one of those is a hidden input to your test outcomes and every one of them needs to be captured.
- Why the recommendation in the project's [`docs/EVALUATION.md`](../EVALUATION.md) is "pin everything that has a seed and capture the version of everything that doesn't" — and how that single sentence took three cycles to learn.

---

*Draft notes for myself: this post should be ~800 words for a tech-blog audience or ~300 words for a LinkedIn post. The technical depth section about `top_p` versus `temperature` can be cut for the LinkedIn version. The "what I check now" checklist is the artifact people will save. The personal-mistake framing ("I should have checked the SDK docs once") is what makes it readable rather than preachy.*
