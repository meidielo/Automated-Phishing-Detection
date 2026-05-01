(function () {
  const authView = document.getElementById("authView");
  const appView = document.getElementById("appView");
  const authNotice = document.getElementById("authNotice");
  const scanNotice = document.getElementById("scanNotice");
  const featureGrid = document.getElementById("featureGrid");
  const historyList = document.getElementById("historyList");
  const decisionStack = document.getElementById("decisionStack");

  let csrfCookieName = "phishdetect_user_csrf";

  function cookieValue(name) {
    const parts = document.cookie.split(";").map((item) => item.trim());
    const match = parts.find((item) => item.startsWith(`${name}=`));
    return match ? decodeURIComponent(match.split("=").slice(1).join("=")) : "";
  }

  function showNotice(element, message) {
    element.textContent = message;
    element.hidden = false;
  }

  function hideNotice(element) {
    element.textContent = "";
    element.hidden = true;
  }

  async function apiJson(path, options) {
    const response = await fetch(path, {
      credentials: "same-origin",
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
      headers: {
        "x-csrf-token": cookieValue(csrfCookieName),
      },
      body: formData,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 402 && payload.locked) {
        throw new Error(payload.locked.reason);
      }
      throw new Error(payload.detail || payload.reason || `Request failed with ${response.status}`);
    }
    return payload;
  }

  function renderAuth(session) {
    authView.classList.remove("hidden");
    appView.classList.add("hidden");
    csrfCookieName = session.csrf_cookie || csrfCookieName;
    if (!session.public_signup_enabled) {
      showNotice(
        authNotice,
        "Account creation is closed on this deployment. Existing accounts can still log in."
      );
    }
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
    featureGrid.innerHTML = "";
    payload.features.forEach((feature) => {
      const card = document.createElement("article");
      card.className = `feature-card ${feature.available ? "available" : "locked"}`;
      const status = feature.available ? "Included" : `Locked: ${feature.required_plan_name}`;
      card.innerHTML = `
        <span class="feature-status">${status}</span>
        <h3>${escapeHtml(feature.name)}</h3>
        <p>${escapeHtml(feature.description)}</p>
      `;
      featureGrid.appendChild(card);
    });
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
    document.getElementById("resultTitle").textContent = payload.verdict;
    decisionStack.innerHTML = "";
    const payment = payload.payment_protection || {};
    const rows = [
      ["Payment decision", payment.decision || "Not payment-specific"],
      ["Score", String(payload.overall_score)],
      ["Locked checks", String((payload.feature_locks || []).length)],
    ];
    rows.forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "result-row";
      row.innerHTML = `<span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong>`;
      decisionStack.appendChild(row);
    });
    if (payload.feature_locks && payload.feature_locks.length) {
      payload.feature_locks.forEach((lock) => {
        const details = lock.details || {};
        const row = document.createElement("div");
        row.className = "result-row";
        row.innerHTML = `
          <span>${escapeHtml(details.feature_slug || "feature")}</span>
          <strong>${escapeHtml(details.required_plan_name || "Upgrade")}</strong>
        `;
        decisionStack.appendChild(row);
      });
    }
    if (payload.account) {
      updateAccount(payload.account);
    }
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  document.querySelectorAll("[data-auth-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-auth-tab]").forEach((tab) => tab.classList.remove("active"));
      button.classList.add("active");
      const mode = button.getAttribute("data-auth-tab");
      document.getElementById("loginForm").classList.toggle("hidden", mode !== "login");
      document.getElementById("signupForm").classList.toggle("hidden", mode !== "signup");
    });
  });

  document.getElementById("loginForm").addEventListener("submit", async (event) => {
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

  document.getElementById("signupForm").addEventListener("submit", async (event) => {
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

  document.getElementById("logoutButton").addEventListener("click", async () => {
    await apiJson("/api/saas/auth/logout", { method: "POST", body: "{}" });
    window.location.reload();
  });

  document.getElementById("scanForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    hideNotice(scanNotice);
    const file = document.getElementById("emailFile").files[0];
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
      showNotice(scanNotice, error.message);
    }
  });

  loadSession().catch((error) => showNotice(authNotice, error.message));
})();
