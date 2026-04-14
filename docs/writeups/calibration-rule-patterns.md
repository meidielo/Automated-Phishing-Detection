# Dampen vs corroborate: a pattern choice for cross-analyzer calibration

*Draft. Cycle 9. Status: not yet polished for external publication.*

---

## The problem

You have a multi-analyzer detection pipeline. Each analyzer is correct in isolation. They produce a weighted ensemble verdict. One specific combination of inputs produces a verdict that is consistently wrong because each individual analyzer is correct *about its own slice of the input* and the average of those correct slices is not the right answer.

Concrete instance from the project this writeup is rooted in: legitimate LinkedIn engagement notifications. The NLP intent analyzer flags the language as social engineering ("12 people viewed your profile this week", "expand your network") because that language is, in fact, indistinguishable from the language phishing kits use. The header analyzer sees SPF + DKIM + DMARC all pass from `linkedin.com`. The URL reputation analyzer sees nothing flagged. The brand impersonation analyzer sees nothing matching its allowlist. The weighted ensemble says SUSPICIOUS, because the NLP analyzer is producing a strong signal at high confidence and nothing else is producing a counter-signal strong enough to balance it.

Three things are simultaneously true:
1. The NLP analyzer is correct: that language is high-risk in isolation
2. The verdict is wrong: the email is legitimate
3. The information needed to reach the right verdict exists in pass 1 — the auth-passes signal from header_analysis is right there, it just isn't reaching the analyzer that needs it

This is not a problem you can solve by retraining the NLP analyzer. The content really is ambiguous. It's not a problem you can solve by raising the SUSPICIOUS threshold without trading off detection of other classes. The content really does look like phishing. **The fix has to live somewhere other than inside the analyzers themselves.**

---

## Two patterns

When you decide to add a cross-analyzer adjustment layer, the first design question is the shape of the adjustment. There are two patterns I see in the wild and they have very different long-term properties.

### Pattern A: Multiplicative dampening

Apply a fixed multiplier to the overall risk score (or to a specific analyzer's contribution) when a corrective condition holds. The LinkedIn case: when header_analysis says SPF+DKIM+DMARC pass and the From: domain is on a known social platform list, multiply the NLP score by 0.5.

```
if auth_passes and from_domain in social_platforms:
    nlp_contribution *= 0.5
```

Pros: trivial to implement, trivially testable, produces a continuous signal that interacts smoothly with the existing weighted scoring.

Cons: the multiplier is a magic number with no calibration data behind it. **Why 0.5 and not 0.3 or 0.7?** The honest answer is "we picked it because it made the FP go away in our test set", and a reviewer who asks the question gets that answer. The answer doesn't generalize, doesn't tell you what to do when the FP set changes, and doesn't survive scaling to a different deployment.

There's a second, subtler problem: multiplicative dampening *hides real risk*. If a future LinkedIn email contains a malicious redirect that the URL reputation analyzer flags, that signal has to be strong enough to overcome the dampening on the NLP signal. You're not just suppressing one path; you're suppressing *the entire risk landscape* for any email matching the dampening condition. You'll catch the ones that produce strong independent signals and miss the ones whose independent signals are real but moderate.

### Pattern B: Corroboration requirement

Don't change the score. Cap the verdict.

```
if auth_passes and from_domain in social_platforms and nlp_is_only_flagger:
    verdict_cap = SUSPICIOUS
```

In words: "If the only analyzer flagging this is the one we know misfires on this input class, AND the auth signals confirm the sender is who they claim to be, then cap the verdict at SUSPICIOUS so an analyst still reviews it but it doesn't auto-escalate. As soon as **any other analyzer** independently flags risk, the cap doesn't apply."

Pros: the rule is a boolean predicate, not a magic number. The defense in an interview is "I require an independent corroborating signal", which is a defendable engineering position rather than a tuning artifact. The underlying score is preserved — a reviewer reading the JSON output sees both the unmodified score (which may still be high) and the cap, with a reasoning string explaining why. Drift in any analyzer remains visible in the score even when the cap is firing. The rule's failure mode is biased toward false positives (analyst review) rather than false negatives (silent drop), which is the right side for a defensive pipeline.

Cons: it's harder to express in a config table because the "corroboration" condition isn't a single threshold — it's a quantifier over the other analyzers. It doesn't compose as cleanly with weighted scoring because the cap operates at the verdict level, not the score level.

---

## Why corroboration wins long-term

The deciding factor for me was the "what does the cap do to a real attack" question.

Imagine a legitimate LinkedIn email — auth-passing, from `linkedin.com` — that embeds a tracking URL pointing to a genuinely malicious redirector. (LinkedIn's tracking URLs have been abused as open redirects multiple times in the wild; this is not hypothetical.) The URL reputation analyzer flags the redirect at, say, risk 0.4 with confidence 0.9. That's below the corroboration threshold of risk ≥ 0.5.

Under multiplicative dampening: the NLP score gets multiplied by 0.5, the URL reputation contribution stays at 0.4, the weighted total is dragged down by both the dampening AND the moderate URL signal. Verdict: probably CLEAN. The malicious redirect slips through because both signals were softened.

Under corroboration: the NLP score is unchanged. The URL reputation signal is below the corroboration threshold so the calibration rule fires. Verdict cap: SUSPICIOUS. **Analyst reviews.** They see the URL reputation flag in the JSON output. They make the call.

The corroboration pattern is **biased toward analyst review** in ambiguous cases. The dampening pattern is **biased toward auto-clean** in ambiguous cases. For a defensive system, the first bias is the right one.

---

## When dampening is actually correct

I don't want to make this sound like dampening is always wrong. There are cases where it's the right call:

- **You have calibration data.** If you have a labeled corpus large enough that you can derive the multiplier from logistic regression rather than picking it by hand, the magic-number objection goes away. Now `* 0.5` isn't magic; it's a coefficient. The interview answer is "we trained the multiplier on a 50k labeled corpus and the coefficient minimizes log loss".
- **The dampening is on a single analyzer's contribution, not the overall score.** If you're adjusting *how much weight one specific analyzer gets in this context*, and the rest of the ensemble is allowed to override it on its own merits, that's a more defensible posture than scaling the whole verdict.
- **The system is hot-path latency-constrained and you can't afford the cost of an analyst-review tier.** A cap at SUSPICIOUS only works if you have an analyst tier to receive the SUSPICIOUS verdicts. If you don't (because you're building an inline mail filter that has to make a yes/no call in milliseconds), then cap-with-review isn't a real option and you're choosing between "definitely block" and "definitely deliver" — at which point dampening is your only option.

The project this writeup comes from has none of those conditions:
- No calibration corpus, so no defensible multiplier value
- The fix needs to operate on the verdict level because the use case is human-in-the-loop
- It has an analyst tier (the dashboard) and the SUSPICIOUS verdict is *designed* to route to it

So corroboration was the right call.

---

## The general pattern

If you're adding cross-analyzer adjustments to any ensemble detection pipeline, ask yourself:

1. **Is the adjustment changing the signal or changing the action?**
   - Multiplicative dampening changes the signal.
   - Verdict caps change the action.
2. **Does the failure mode of the adjustment land on false-positive or false-negative?**
   - Dampening biases toward FN (silent drop)
   - Capping toward FP (analyst review)
   - For a defensive system the FP bias is almost always preferable.
3. **Can you defend the parameters?**
   - Continuous parameters (multipliers, thresholds) need calibration data
   - Boolean predicates need only a logical justification.
4. **Does the adjustment preserve the underlying signal for inspection?**
   - Dampening usually rewrites the score in place
   - Capping can be implemented as "verdict ceiling" with the score preserved.
   - The second is dramatically more debuggable when something goes wrong six months later.
5. **What does an attacker do with the adjustment?**
   - Both patterns create a class of input where the adjustment fires.
   - With dampening, attackers want to *match* the firing class because it makes them harder to detect.
   - With capping, attackers want to match the firing class because it caps their verdict at SUSPICIOUS rather than CONFIRMED — which still gets them reviewed by a human, which is much weaker leverage.

The asymmetric attacker leverage on (5) is the strongest single argument for corroboration. The whole point of detection is to make the attacker's job harder. A pattern that gives the attacker a known class of inputs they can match to silently bypass the detector is a pattern you should not ship if you have any alternative.

---

## What I'd write if this were a longer post

- The "10-rule cap" discipline that pairs with the corroboration pattern in the project — without a hard cap on calibration rules, the pattern degenerates into a dumping ground regardless of which formulation you pick.
- The interaction between calibration rules and analyst review queues — calibration that fires often is itself a signal you should plot, because it tells you which input classes your analyzers are systematically wrong about.
- Why "preserving the underlying score" is a stronger property than it looks: it lets you build an eval harness that compares calibrated-vs-uncalibrated verdicts on the same corpus, which is the cleanest possible regression detector for analyzer drift.
- The history of dampening as a pattern in non-detection contexts (recommender systems, ad-ranking pipelines) and why those settings are different enough that the conclusions don't transfer.

---

*Draft notes for myself: this is more senior-engineer-flavored than the NLP non-determinism post. The audience is people thinking about the same design space, not people who haven't encountered it. Length: ~1500 words. The asymmetric-attacker-leverage argument in the numbered list is the part to lead with if I cut this for a conference talk. The "when dampening is actually correct" section is what makes the argument feel honest rather than dogmatic — without it, the post reads as one-sided.*
