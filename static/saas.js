(function () {
  const authView = document.getElementById("authView");
  const appView = document.getElementById("appView");
  const authNotice = document.getElementById("authNotice");
  const authTitle = document.getElementById("authTitle");
  const authSubtext = document.getElementById("authSubtext");
  const scanNotice = document.getElementById("scanNotice");
  const billingNotice = document.getElementById("billingNotice");
  const pricingSection = document.getElementById("pricingSection");
  const billingCycle = document.getElementById("billingCycle");
  const planGrid = document.getElementById("planGrid");
  const featureGrid = document.getElementById("featureGrid");
  const historyList = document.getElementById("historyList");
  const decisionStack = document.getElementById("decisionStack");
  const emailFileInput = document.getElementById("emailFile");
  const scanDropZone = document.getElementById("scanDropZone");
  const scanDropTitle = document.getElementById("scanDropTitle");
  const scanDropHint = document.getElementById("scanDropHint");
  const scanSubmitButton = document.getElementById("scanSubmitButton");
  const scanClearButton = document.getElementById("scanClearButton");
  const authForms = {
    login: document.getElementById("loginForm"),
    signup: document.getElementById("signupForm"),
    reset: document.getElementById("resetRequestForm"),
    resetConfirm: document.getElementById("resetConfirmForm"),
  };

  let csrfCookieName = "phishdetect_user_csrf";
  let featureCatalog = new Map();
  let publicSignupEnabled = true;
  let selectedBillingInterval = "monthly";
  let lastPlansPayload = null;
  let selectedScanFile = null;
  const planOrder = ["free", "starter", "pro", "business"];
  const defaultScanDropTitle = "Drop your .eml file here, or click to browse";
  const defaultScanDropHint = "Payment-risk scans use .eml files";

  function planRank(slug) {
    const rank = planOrder.indexOf(String(slug || "").toLowerCase());
    return rank >= 0 ? rank : 0;
  }

  function highestPlanSlug() {
    return planOrder[planOrder.length - 1];
  }

  function cookieValue(name) {
    const parts = document.cookie.split(";").map((item) => item.trim());
    const match = parts.find((item) => item.startsWith(`${name}=`));
    return match ? decodeURIComponent(match.split("=").slice(1).join("=")) : "";
  }

  function showNotice(element, message) {
    element.textContent = message;
    element.hidden = false;
  }

  function showUpgradeNotice(element, message) {
    element.innerHTML = `
      <span>${escapeHtml(message)}</span>
      <button class="notice-action" type="button" data-upgrade-trigger>View upgrade options</button>
    `;
    element.hidden = false;
  }

  function openUpgradePanel(message) {
    if (!pricingSection) {
      return;
    }
    pricingSection.classList.remove("hidden");
    if (message) {
      showUpgradeNotice(billingNotice, message);
    }
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    pricingSection.scrollIntoView({
      behavior: prefersReducedMotion ? "auto" : "smooth",
      block: "start",
    });
  }

  function closeUpgradePanel() {
    if (pricingSection) {
      pricingSection.classList.add("hidden");
    }
  }

  function hideNotice(element) {
    element.textContent = "";
    element.hidden = true;
  }

  function billingErrorMessage(error) {
    const message = String(error && error.message ? error.message : error || "");
    if (/stripe|billing|checkout|portal|502|503/i.test(message)) {
      return "Billing is not available right now. The server needs a valid Stripe secret key before checkout can start.";
    }
    return message || "Billing is not available right now.";
  }

  function billingIntervalLabel() {
    return selectedBillingInterval === "yearly" ? "/ month, billed yearly" : "/ month";
  }

  async function apiJson(path, options) {
    const response = await fetch(path, {
      credentials: "same-origin",
      referrerPolicy: "same-origin",
      headers: {
        "content-type": "application/json",
        "x-csrf-token": cookieValue(csrfCookieName),
        ...(options && options.headers ? options.headers : {}),
      },
      ...options,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.detail || payload.reason || `Request failed with ${response.status}`);
    }
    return payload;
  }

  async function apiForm(path, formData) {
    const response = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      referrerPolicy: "same-origin",
      headers: {
        "x-csrf-token": cookieValue(csrfCookieName),
      },
      body: formData,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = payload.detail || payload.reason || `Request failed with ${response.status}`;
      const error = new Error(response.status === 402 && payload.locked ? payload.locked.reason : message);
      error.status = response.status;
      error.payload = payload;
      if (response.status === 402 && payload.locked) {
        error.locked = payload.locked;
      }
      throw error;
    }
    return payload;
  }

  function renderAuth(session) {
    authView.classList.remove("hidden");
    appView.classList.add("hidden");
    csrfCookieName = session.csrf_cookie || csrfCookieName;
    publicSignupEnabled = Boolean(session.public_signup_enabled);
    selectAuthMode("login");
  }

  async function renderApp(session) {
    authView.classList.add("hidden");
    appView.classList.remove("hidden");
    csrfCookieName = session.csrf_cookie || csrfCookieName;
    updateAccount(session.account);
    await Promise.all([loadPlans(), loadHistory()]);
  }

  function updateAccount(account) {
    document.getElementById("orgLabel").textContent = account.org_name;
    document.getElementById("planName").textContent = account.plan_name;
    document.getElementById("userEmail").textContent = account.email;
    document.getElementById("usageText").textContent =
      `${account.monthly_scan_used} / ${account.monthly_scan_quota}`;
    const upgradeButton = document.getElementById("upgradeButton");
    const portalButton = document.getElementById("portalButton");
    const billingHelp = document.getElementById("billingHelp");
    const hasStripeCustomer = Boolean(account.stripe_customer_id);
    const isHighestPlan = account.plan_slug === highestPlanSlug();
    upgradeButton.textContent = isHighestPlan ? "Plan details" : "Upgrade";
    upgradeButton.setAttribute(
      "aria-label",
      isHighestPlan ? "View plan details" : "View upgrade options",
    );
    portalButton.disabled = !hasStripeCustomer;
    portalButton.textContent = hasStripeCustomer ? "Manage billing" : "Billing portal locked";
    billingHelp.textContent = hasStripeCustomer
      ? "Manage invoices, cards, and subscription changes in Stripe."
      : isHighestPlan
        ? "You are already on the highest plan. Billing portal appears after first checkout."
        : "Use Upgrade when you need more scans or paid checks.";
    const pct = account.monthly_scan_quota > 0
      ? Math.min((account.monthly_scan_used / account.monthly_scan_quota) * 100, 100)
      : 0;
    document.getElementById("usageBar").style.width = `${pct}%`;
  }

  async function loadSession() {
    const session = await apiJson("/api/saas/session");
    if (session.authenticated) {
      await renderApp(session);
    } else {
      renderAuth(session);
    }
  }

  async function loadPlans() {
    const payload = await apiJson("/api/saas/plans");
    updateAccount(payload.account);
    featureCatalog = new Map(payload.features.map((feature) => [feature.slug, feature]));
    renderPricing(payload);
    renderFeatureAccess(payload);
  }

  function renderPlans(payload) {
    const currentPlan = payload.current_plan || "free";
    planGrid.innerHTML = "";
    payload.plans.forEach((plan) => {
      const isCurrent = plan.slug === currentPlan;
      const isFree = plan.slug === "free";
      const card = document.createElement("article");
      card.className = `plan-card ${isCurrent ? "current" : ""}`;
      const price = plan.monthly_price_aud > 0 ? `A$${plan.monthly_price_aud}/mo` : "Free";
      const buttonText = isCurrent ? "Current plan" : (isFree ? "Included" : `Upgrade to ${plan.name}`);
      card.innerHTML = `
        <span class="feature-status">${escapeHtml(plan.best_for)}</span>
        <h3>${escapeHtml(plan.name)}</h3>
        <div class="plan-price">${escapeHtml(price)}</div>
        <p>${escapeHtml(plan.summary)}</p>
        <p>${plan.scan_quota} scans/month · ${plan.mailbox_quota} mailboxes</p>
        <button type="button" data-plan="${escapeHtml(plan.slug)}" ${isCurrent || isFree ? "disabled" : ""}>
          ${escapeHtml(buttonText)}
        </button>
      `;
      planGrid.appendChild(card);
    });
  }

  function renderPricing(payload) {
    const currentPlan = payload.current_plan || "free";
    const currentRank = planRank(currentPlan);
    const maxPlanRank = Math.max(...payload.plans.map((plan) => planRank(plan.slug)));
    const isHighestPlan = currentRank >= maxPlanRank;
    const pricingTitle = document.getElementById("pricingTitle");
    const pricingDescription = document.getElementById("pricingDescription");
    if (pricingTitle && pricingDescription) {
      pricingTitle.textContent = isHighestPlan ? "Plan coverage" : "Upgrade options";
      pricingDescription.textContent = isHighestPlan
        ? "You are already on the highest plan. Lower tiers are included here for comparison."
        : "Open this when you need more scans, mailbox monitoring, or paid API-backed checks.";
    }
    lastPlansPayload = payload;
    planGrid.innerHTML = "";
    payload.plans.forEach((plan, index) => {
      const targetRank = planRank(plan.slug);
      const isCurrent = plan.slug === currentPlan;
      const isCovered = targetRank < currentRank;
      const canUpgrade = targetRank > currentRank;
      const isFree = plan.slug === "free";
      const card = document.createElement("article");
      card.className = `plan-card ${isCurrent ? "current" : ""} ${isCovered ? "covered" : ""}`;
      const priceValue = selectedBillingInterval === "yearly"
        ? Number(plan.yearly_monthly_price_aud || plan.monthly_price_aud || 0)
        : Number(plan.monthly_price_aud || 0);
      const price = priceValue > 0 ? `A$${formatMoney(priceValue)}` : "A$0";
      const yearlyTotal = Number(plan.yearly_price_aud || (priceValue * 12));
      const billingNote = isFree
        ? "No card needed"
        : selectedBillingInterval === "yearly"
          ? `Billed A$${formatMoney(yearlyTotal)} yearly`
          : "Billed monthly";
      const savings = Number(plan.yearly_savings_percent || 0);
      const savingsBadge = selectedBillingInterval === "yearly" && savings > 0
        ? `<span class="plan-badge save">Save ${escapeHtml(String(savings))}%</span>`
        : "";
      const priceCadence = isFree ? "" : `<small>${escapeHtml(billingIntervalLabel())}</small>`;
      const buttonText = isCurrent
        ? "Current plan"
        : isCovered || isFree
          ? "Included"
          : `Upgrade to ${plan.name}`;
      const previousPlan = payload.plans[index - 1];
      const directFeatures = payload.features.filter((feature) => feature.minimum_plan === plan.slug);
      const featureIntro = isFree
        ? "Included in Free:"
        : `Everything in ${previousPlan ? previousPlan.name : "the previous plan"}, plus:`;
      const featureItems = directFeatures
        .slice(0, 3)
        .map((feature) => `<li>${escapeHtml(feature.name)}</li>`)
        .join("");
      card.innerHTML = `
        <div class="plan-card-head">
          <div>
            <h3>${escapeHtml(plan.name)}</h3>
            <p class="plan-audience">${escapeHtml(plan.best_for)}</p>
          </div>
          <div class="plan-card-badges">
            ${savingsBadge}
            ${isCovered ? '<span class="plan-badge included">Included</span>' : ""}
            ${isCurrent ? '<span class="plan-badge">Current</span>' : ""}
          </div>
        </div>
        <div class="plan-price"><span>${escapeHtml(price)}</span>${priceCadence}</div>
        <div class="plan-billing-note">${escapeHtml(billingNote)}</div>
        <p class="plan-summary">${escapeHtml(plan.summary)}</p>
        <div class="plan-limits">
          <span>${escapeHtml(formatCount(plan.scan_quota, "scan"))} / month</span>
          <span>${escapeHtml(formatCount(plan.mailbox_quota, "mailbox"))}</span>
        </div>
        <button type="button" data-plan="${escapeHtml(plan.slug)}" ${canUpgrade ? "" : "disabled"}>
          ${escapeHtml(buttonText)}
        </button>
        <div class="plan-divider"></div>
        <div class="plan-feature-list">
          <strong>${escapeHtml(featureIntro)}</strong>
          <ul>${featureItems}</ul>
        </div>
      `;
      planGrid.appendChild(card);
    });
  }

  function renderFeatureAccess(payload) {
    const currentName = payload.account ? payload.account.plan_name : "current plan";
    const included = payload.features.filter((feature) => feature.available);
    const locked = payload.features.filter((feature) => !feature.available);
    featureGrid.innerHTML = `
      <article class="access-card">
        <h3>Included in ${escapeHtml(currentName)}</h3>
        <ul>${featureRows(included, "included")}</ul>
      </article>
      <article class="access-card locked">
        <h3>Locked until upgrade</h3>
        <ul>${featureRows(locked, "locked")}</ul>
      </article>
    `;
  }

  function featureRows(features, mode) {
    if (!features.length) {
      return "<li><span>All available</span><small>No locked checks on this plan.</small></li>";
    }
    return features.map((feature) => {
      const meta = mode === "locked"
        ? `${feature.category} - ${feature.required_plan_name}`
        : feature.category;
      return `
        <li>
          <span>${escapeHtml(feature.name)}</span>
          <small>${escapeHtml(meta)}</small>
        </li>
      `;
    }).join("");
  }

  function planIcon(index) {
    const branch = index >= 2
      ? '<path d="M20 41L32 34L44 41" /><circle cx="44" cy="41" r="4" />'
      : '<path d="M32 34L44 41" /><circle cx="44" cy="41" r="4" />';
    const extraBranch = index >= 3
      ? '<path d="M20 41L12 47M44 41L52 47" /><circle cx="12" cy="47" r="3" /><circle cx="52" cy="47" r="3" />'
      : "";
    return `
      <svg viewBox="0 0 64 64" focusable="false" aria-hidden="true">
        <circle cx="32" cy="14" r="10" />
        <circle cx="32" cy="14" r="4" />
        <path d="M32 24V50" />
        <path d="M32 34L20 41" />
        <circle cx="20" cy="41" r="4" />
        ${branch}
        ${extraBranch}
      </svg>
    `;
  }

  function formatCount(value, label) {
    const count = Number(value || 0);
    const plural = label === "mailbox" ? "mailboxes" : `${label}s`;
    const suffix = count === 1 ? label : plural;
    return `${count.toLocaleString()} ${suffix}`;
  }

  function formatMoney(value) {
    const amount = Number(value || 0);
    if (!Number.isFinite(amount)) {
      return "0";
    }
    return amount % 1 === 0
      ? amount.toLocaleString("en-AU", { maximumFractionDigits: 0 })
      : amount.toLocaleString("en-AU", {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        });
  }

  function formatBytes(bytes) {
    const size = Number(bytes || 0);
    if (size < 1024) {
      return `${size} B`;
    }
    if (size < 1024 * 1024) {
      return `${(size / 1024).toFixed(1)} KB`;
    }
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  }

  function setScanFile(file) {
    if (!file) {
      return;
    }
    if (!/\.eml$/i.test(file.name || "")) {
      clearScanFile();
      showNotice(scanNotice, "Use an .eml file for this workspace scan.");
      return;
    }
    selectedScanFile = file;
    scanDropTitle.textContent = file.name;
    scanDropHint.textContent = `${formatBytes(file.size)} selected`;
    scanDropZone.classList.add("has-file");
    scanSubmitButton.disabled = false;
    scanClearButton.hidden = false;
    hideNotice(scanNotice);
  }

  function clearScanFile() {
    selectedScanFile = null;
    emailFileInput.value = "";
    scanDropTitle.textContent = defaultScanDropTitle;
    scanDropHint.textContent = defaultScanDropHint;
    scanDropZone.classList.remove("has-file", "drag-over");
    scanSubmitButton.disabled = true;
    scanClearButton.hidden = true;
  }

  async function loadHistory() {
    const payload = await apiJson("/api/saas/scans?limit=8");
    historyList.innerHTML = "";
    if (!payload.results.length) {
      const empty = document.createElement("article");
      empty.className = "history-card";
      empty.innerHTML = "<p>No account scans yet.</p>";
      historyList.appendChild(empty);
      return;
    }
    payload.results.forEach((item) => {
      const subject = item.result && item.result.iocs && item.result.iocs.headers
        ? item.result.iocs.headers.subject || item.email_id
        : item.email_id;
      const card = document.createElement("article");
      card.className = "history-card";
      card.innerHTML = `
        <div>
          <h3>${escapeHtml(subject)}</h3>
          <p>${escapeHtml(item.created_at)}</p>
        </div>
        <span class="badge">${escapeHtml(item.verdict)}</span>
      `;
      historyList.appendChild(card);
    });
  }

  function renderResult(payload) {
    document.getElementById("resultTitle").textContent = "Latest analysis";
    const panelNote = document.querySelector("#resultPanel .panel-note");
    if (panelNote) {
      panelNote.textContent = "Review the decision, risk score, and any paid checks skipped by the current plan.";
    }
    decisionStack.innerHTML = "";
    const payment = payload.payment_protection || {};
    const decision = payment.decision || "Not payment-specific";
    const lockedChecks = payload.feature_locks || [];
    const score = normalizedScore(payload.overall_score);
    const decisionClass = decisionStyle(decision);
    decisionStack.innerHTML = `
      <section class="result-verdict ${decisionClass}" aria-label="Payment decision">
        <div>
          <span class="result-kicker">Payment decision</span>
          <strong>${escapeHtml(formatDecision(decision))}</strong>
          <p>${escapeHtml(decisionGuidance(decision, payload.verdict))}</p>
        </div>
        <div class="result-score-card">
          <span>Risk score</span>
          <strong>${escapeHtml(formatPercent(score))}</strong>
          <div class="result-score-meter" aria-hidden="true"><span></span></div>
        </div>
      </section>
      <section class="result-summary-grid" aria-label="Analysis summary">
        <article>
          <span>Pipeline verdict</span>
          <strong>${escapeHtml(formatLabel(payload.verdict || "Unknown"))}</strong>
        </article>
        <article>
          <span>Checks available now</span>
          <strong>${escapeHtml(String(Math.max(Object.keys(payload.analyzer_results || {}).length - lockedChecks.length, 0)))}</strong>
        </article>
        <article>
          <span>Plan-gated checks</span>
          <strong>${escapeHtml(String(lockedChecks.length))}</strong>
        </article>
      </section>
      ${renderLockedChecks(lockedChecks)}
    `;
    const scoreFill = decisionStack.querySelector(".result-score-meter span");
    if (scoreFill) {
      scoreFill.style.width = `${Math.round(score * 100)}%`;
    }
    if (payload.account) {
      updateAccount(payload.account);
    }
  }

  function renderLockedChecks(locks) {
    if (!locks.length) {
      return `
        <section class="result-locks clear">
          <h3>All checks on your plan completed</h3>
          <p>No paid API-backed analyzer was skipped for this scan.</p>
        </section>
      `;
    }
    const rows = locks.map((lock) => {
      const details = lock.details || {};
      const slug = details.feature_slug || "";
      const feature = featureCatalog.get(slug) || {};
      const requiredPlan = details.required_plan_name || feature.required_plan_name || "Upgrade";
      return `
        <article class="locked-check-card">
          <div>
            <strong>${escapeHtml(feature.name || formatLabel(slug || "Locked check"))}</strong>
            <p>${escapeHtml(feature.description || "This analyzer is available on a higher plan.")}</p>
          </div>
          <span>${escapeHtml(requiredPlan)}</span>
        </article>
      `;
    }).join("");
    return `
      <section class="result-locks">
        <div class="result-locks-heading">
          <div>
            <h3>Skipped until upgrade</h3>
            <p>These paid checks were not run on the current plan.</p>
          </div>
          <button class="subtle-button" type="button" data-upgrade-trigger>Upgrade</button>
        </div>
        <div class="locked-check-list">${rows}</div>
      </section>
    `;
  }

  function normalizedScore(value) {
    const score = Number(value || 0);
    if (!Number.isFinite(score)) {
      return 0;
    }
    return Math.max(0, Math.min(score, 1));
  }

  function formatPercent(score) {
    return `${(score * 100).toFixed(score >= 0.1 ? 1 : 2)}%`;
  }

  function formatLabel(value) {
    return String(value || "")
      .replace(/[_-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase()
      .replace(/\b\w/g, (char) => char.toUpperCase());
  }

  function formatDecision(value) {
    const decision = String(value || "").toUpperCase();
    if (decision === "DO_NOT_PAY") {
      return "Do not pay";
    }
    if (decision === "VERIFY") {
      return "Verify before payment";
    }
    if (decision === "SAFE") {
      return "Safe to continue";
    }
    return formatLabel(value || "Not payment-specific");
  }

  function decisionStyle(value) {
    const decision = String(value || "").toUpperCase();
    if (decision === "DO_NOT_PAY") {
      return "block";
    }
    if (decision === "VERIFY") {
      return "verify";
    }
    if (decision === "SAFE") {
      return "safe";
    }
    return "neutral";
  }

  function decisionGuidance(decision, verdict) {
    const normalized = String(decision || "").toUpperCase();
    if (normalized === "DO_NOT_PAY") {
      return "Block payment release and confirm the request through a trusted channel.";
    }
    if (normalized === "VERIFY") {
      return "Hold payment and verify the supplier or bank-detail change outside email.";
    }
    if (normalized === "SAFE") {
      return "Continue normal approval, while keeping the scan result in the workspace history.";
    }
    return `Pipeline verdict: ${formatLabel(verdict || "Unknown")}. Review the evidence before acting.`;
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function authModeCopy(mode) {
    const copy = {
      login: {
        title: "Sign in to your workspace",
        subtext: "Enter your email and password to continue.",
      },
      signup: {
        title: "Create your workspace",
        subtext: "Start a free workspace for manual payment-email scans.",
      },
      reset: {
        title: "Reset your password",
        subtext: "Enter your email and we will send a reset link if the account exists.",
      },
      resetConfirm: {
        title: "Choose a new password",
        subtext: "Set a new password to return to your workspace.",
      },
    };
    return copy[mode] || copy.login;
  }

  function selectAuthMode(mode) {
    const requestedMode = mode;
    if (mode === "signup" && !publicSignupEnabled) {
      mode = "login";
      showNotice(authNotice, "Account creation is invite-only on this deployment.");
    }
    const copy = authModeCopy(mode);
    authTitle.textContent = copy.title;
    authSubtext.textContent = copy.subtext;
    authForms.login.classList.toggle("hidden", mode !== "login");
    authForms.signup.classList.toggle("hidden", mode !== "signup");
    authForms.reset.classList.toggle("hidden", mode !== "reset");
    authForms.resetConfirm.classList.toggle("hidden", mode !== "resetConfirm");
    if (requestedMode !== "signup" && authNotice.textContent === "Account creation is invite-only on this deployment.") {
      hideNotice(authNotice);
    }
  }

  document.querySelectorAll("[data-auth-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      hideNotice(authNotice);
      selectAuthMode(button.getAttribute("data-auth-mode"));
    });
  });

  authForms.login.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideNotice(authNotice);
    const form = new FormData(event.currentTarget);
    try {
      await apiJson("/api/saas/auth/login", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      await loadSession();
    } catch (error) {
      showNotice(authNotice, error.message);
    }
  });

  authForms.signup.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideNotice(authNotice);
    const form = new FormData(event.currentTarget);
    try {
      await apiJson("/api/saas/auth/signup", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      await loadSession();
    } catch (error) {
      showNotice(authNotice, error.message);
    }
  });

  authForms.reset.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideNotice(authNotice);
    const form = new FormData(event.currentTarget);
    try {
      const payload = await apiJson("/api/saas/auth/password-reset/request", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      showNotice(authNotice, payload.message);
    } catch (error) {
      showNotice(authNotice, error.message);
    }
  });

  authForms.resetConfirm.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideNotice(authNotice);
    const form = new FormData(event.currentTarget);
    try {
      await apiJson("/api/saas/auth/password-reset/confirm", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(form.entries())),
      });
      window.history.replaceState({}, "", "/app");
      await loadSession();
    } catch (error) {
      showNotice(authNotice, error.message);
    }
  });

  document.getElementById("logoutButton").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    hideNotice(billingNotice);
    try {
      await apiJson("/api/saas/auth/logout", { method: "POST", body: "{}" });
      await loadSession();
    } catch (error) {
      button.disabled = false;
      showNotice(billingNotice, error.message || "Logout failed. Refresh and try again.");
    }
  });

  document.getElementById("upgradeButton").addEventListener("click", () => {
    hideNotice(billingNotice);
    openUpgradePanel();
  });

  document.getElementById("closePricingButton").addEventListener("click", () => {
    closeUpgradePanel();
    hideNotice(billingNotice);
  });

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-upgrade-trigger]");
    if (!trigger) {
      return;
    }
    event.preventDefault();
    openUpgradePanel();
  });

  billingCycle.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-billing-interval]");
    if (!button) {
      return;
    }
    selectedBillingInterval = button.getAttribute("data-billing-interval") || "monthly";
    billingCycle.querySelectorAll("button[data-billing-interval]").forEach((item) => {
      const active = item === button;
      item.classList.toggle("active", active);
      item.setAttribute("aria-pressed", active ? "true" : "false");
    });
    if (lastPlansPayload) {
      renderPricing(lastPlansPayload);
    }
  });

  planGrid.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-plan]");
    if (!button || button.disabled) {
      return;
    }
    hideNotice(billingNotice);
    button.disabled = true;
    const originalText = button.textContent;
    button.textContent = "Opening Checkout";
    try {
      const payload = await apiJson("/api/saas/billing/checkout", {
        method: "POST",
        body: JSON.stringify({
          plan: button.getAttribute("data-plan"),
          billing_interval: selectedBillingInterval,
        }),
      });
      if (!payload.checkout_url) {
        throw new Error("Stripe did not return a Checkout URL.");
      }
      window.location.href = payload.checkout_url;
    } catch (error) {
      showNotice(billingNotice, billingErrorMessage(error));
      button.disabled = false;
      button.textContent = originalText;
    }
  });

  document.getElementById("portalButton").addEventListener("click", async () => {
    const portalButton = document.getElementById("portalButton");
    if (portalButton.disabled) {
      return;
    }
    hideNotice(billingNotice);
    try {
      const payload = await apiJson("/api/saas/billing/portal", {
        method: "POST",
        body: "{}",
      });
      if (!payload.portal_url) {
        throw new Error("Stripe did not return a billing portal URL.");
      }
      window.location.href = payload.portal_url;
    } catch (error) {
      showNotice(billingNotice, billingErrorMessage(error));
    }
  });

  scanDropZone.addEventListener("click", () => {
    emailFileInput.click();
  });

  scanDropZone.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") {
      return;
    }
    event.preventDefault();
    emailFileInput.click();
  });

  emailFileInput.addEventListener("change", (event) => {
    setScanFile(event.currentTarget.files[0]);
  });

  scanClearButton.addEventListener("click", () => {
    clearScanFile();
    hideNotice(scanNotice);
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    scanDropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      scanDropZone.classList.add("drag-over");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    scanDropZone.addEventListener(eventName, () => {
      scanDropZone.classList.remove("drag-over");
    });
  });

  scanDropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    setScanFile(event.dataTransfer.files[0]);
  });

  document.getElementById("scanForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    hideNotice(scanNotice);
    const file = selectedScanFile || emailFileInput.files[0];
    if (!file) {
      showNotice(scanNotice, "Choose an .eml file first.");
      return;
    }
    const form = new FormData();
    form.append("file", file);
    try {
      const payload = await apiForm("/api/saas/analyze/upload", form);
      renderResult(payload);
      await Promise.all([loadPlans(), loadHistory()]);
    } catch (error) {
      if (error.status === 402) {
        showUpgradeNotice(scanNotice, `${error.message} Upgrade to keep scanning.`);
      } else {
        showNotice(scanNotice, error.message);
      }
    }
  });

  function prepareResetLink() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("reset_token");
    if (!token) {
      return false;
    }
    document.getElementById("resetToken").value = token;
    selectAuthMode("resetConfirm");
    return true;
  }

  const hasResetToken = prepareResetLink();
  if (!hasResetToken) {
    loadSession().catch((error) => showNotice(authNotice, error.message));
  }
})();
