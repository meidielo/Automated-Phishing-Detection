(function () {
  const state = { samples: [], activeIndex: 0 };

  const tabs = document.getElementById("sample-tabs");
  const emailDecision = document.getElementById("email-decision");
  const emailMeta = document.getElementById("email-meta");
  const decisionLabel = document.getElementById("decision-label");
  const riskScore = document.getElementById("risk-score");
  const riskFill = document.getElementById("risk-fill");
  const summaryText = document.getElementById("summary-text");
  const nextAction = document.getElementById("next-action");
  const signalCount = document.getElementById("signal-count");
  const signalList = document.getElementById("signal-list");
  const verificationSteps = document.getElementById("verification-steps");
  const jsonOutput = document.getElementById("json-output");

  function text(value) {
    return value == null || value === "" ? "None" : String(value);
  }

  function decisionTitle(value) {
    return String(value || "").replace(/_/g, " ");
  }

  function setMeta(label, value) {
    const row = document.createElement("div");
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = label;
    dd.textContent = text(value);
    row.append(dt, dd);
    return row;
  }

  function renderTabs() {
    tabs.innerHTML = "";
    state.samples.forEach((sample, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = decisionTitle(sample.decision);
      button.className = index === state.activeIndex ? "active" : "";
      button.addEventListener("click", () => {
        state.activeIndex = index;
        render();
      });
      tabs.appendChild(button);
    });
  }

  function renderSignals(sample) {
    const signals = sample.signals || [];
    signalCount.textContent = `${signals.length} signal${signals.length === 1 ? "" : "s"}`;
    signalList.innerHTML = "";

    if (signals.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "No material payment scam signals found.";
      signalList.appendChild(empty);
      return;
    }

    signals.forEach((signal) => {
      const item = document.createElement("article");
      item.className = "signal-item";

      const header = document.createElement("header");
      const title = document.createElement("strong");
      const severity = document.createElement("span");
      title.textContent = text(signal.name).replace(/_/g, " ");
      severity.className = "severity";
      severity.textContent = text(signal.severity);
      header.append(title, severity);

      const evidence = document.createElement("p");
      const recommendation = document.createElement("p");
      evidence.textContent = text(signal.evidence);
      recommendation.textContent = text(signal.recommendation);

      item.append(header, evidence, recommendation);
      signalList.appendChild(item);
    });
  }

  function renderSteps(sample) {
    verificationSteps.innerHTML = "";
    (sample.verification_steps || []).forEach((step) => {
      const item = document.createElement("li");
      item.textContent = step;
      verificationSteps.appendChild(item);
    });
  }

  function render() {
    const sample = state.samples[state.activeIndex];
    renderTabs();
    if (!sample) {
      return;
    }

    const email = sample.email || {};
    emailDecision.textContent = decisionTitle(sample.decision);
    emailMeta.innerHTML = "";
    emailMeta.append(
      setMeta("Subject", email.subject),
      setMeta("From", email.from_address),
      setMeta("Reply-To", email.reply_to),
      setMeta("Scenario", sample.scenario),
      setMeta("Source", `${sample.source_type || "sample"} / ${sample.split || "demo"}`)
    );

    decisionLabel.textContent = decisionTitle(sample.decision);
    riskScore.textContent = Number(sample.risk_score || 0).toFixed(3);
    riskFill.style.width = `${Math.max(0, Math.min(1, Number(sample.risk_score || 0))) * 100}%`;
    summaryText.textContent = sample.summary || "";
    nextAction.textContent = sample.agent_next_action || "";

    renderSignals(sample);
    renderSteps(sample);
    jsonOutput.textContent = JSON.stringify(sample, null, 2);
  }

  function renderError(message) {
    document.querySelector(".agent-workbench").classList.add("error-state");
    summaryText.textContent = message;
    jsonOutput.textContent = JSON.stringify({ error: message }, null, 2);
  }

  fetch("/api/demo/agent-payment-analysis")
    .then((response) => {
      if (!response.ok) {
        throw new Error(`Demo API returned ${response.status}`);
      }
      return response.json();
    })
    .then((payload) => {
      state.samples = payload.samples || [];
      state.activeIndex = 0;
      render();
    })
    .catch((error) => {
      renderError(error.message || "Agent demo unavailable.");
    });
})();
