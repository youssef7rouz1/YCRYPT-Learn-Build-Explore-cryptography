document.addEventListener("DOMContentLoaded", () => {
  const htmlEl      = document.documentElement;
  const themeBtn    = document.getElementById("theme-toggle");
  const themeIcon   = document.getElementById("theme-icon");
  const catSelect   = document.getElementById("category");
  const algoSelect  = document.getElementById("algorithm");
  const paramFields = document.getElementById("param-fields");
  const runBtn      = document.getElementById("run-btn");
  const copyBtn     = document.getElementById("copy-btn");
  const outputPre   = document.getElementById("output");
  const toastEl     = document.getElementById("copy-toast");
  const copyToast   = new bootstrap.Toast(toastEl);

  // 1. Tooltips
  document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
    new bootstrap.Tooltip(el);
  });

  // 2. Theme Toggle
  const stored = localStorage.getItem("theme") || "light";
  htmlEl.setAttribute("data-theme", stored);
  updateIcon(stored);
  themeBtn.addEventListener("click", () => {
    const next = htmlEl.getAttribute("data-theme") === "light" ? "dark" : "light";
    htmlEl.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
    updateIcon(next);
  });
  function updateIcon(theme) {
    themeIcon.className = theme === "light" ? "bi bi-moon-fill" : "bi bi-sun-fill";
  }

  // 3. Category → Algorithm
  catSelect.addEventListener("change", () => {
    algoSelect.innerHTML = `<option value="" disabled selected>Select algo…</option>`;
    paramFields.innerHTML = "";
    outputPre.textContent = "";
    runBtn.disabled = false;

    (ALGOS[catSelect.value] || []).forEach(({key, label}) => {
      const o = document.createElement("option");
      o.value = key; o.textContent = label;
      algoSelect.append(o);
    });
  });

  // 4. Algorithm → Params (with Encrypt/Decrypt toggling)
  algoSelect.addEventListener("change", () => {
    paramFields.innerHTML = "";
    outputPre.textContent = "";

    const specs = ALGO_PARAMS[algoSelect.value] || [];
    let actionSelect = null;

    specs.forEach(s => {
      const wrapper = document.createElement("div");
      wrapper.className = "mb-3";
      if (s.show_when) {
        wrapper.style.display = "none";
        wrapper.dataset.showWhen = s.show_when;
      }

      // label
      if (s.label) {
        const lbl = document.createElement("label");
        lbl.htmlFor = s.name;
        lbl.className = "form-label";
        lbl.textContent = s.label;
        wrapper.append(lbl);
      }

      // input/select/textarea
      let input;
      if (s.type === "textarea") {
        input = document.createElement("textarea");
        input.className = "form-control";
        input.rows = s.rows || 3;
      }
      else if (s.type === "select") {
        input = document.createElement("select");
        input.className = "form-select";
        s.options.forEach(opt => {
          const o = document.createElement("option");
          o.value = o.textContent = opt;
          input.append(o);
        });
      }
      else {
        input = document.createElement("input");
        input.type = s.type;
        input.className = "form-control";
        if (s.min != null)   input.min         = s.min;
        if (s.max != null)   input.max         = s.max;
        if (s.value != null) input.value       = s.value;
      }

      // common attrs
      input.id = s.name;
      input.name = s.name;
      if (s.required)    input.required    = true;
      if (s.placeholder) input.placeholder = s.placeholder;

      wrapper.append(input);
      paramFields.append(wrapper);

      if (s.name === "action") {
        actionSelect = input;
      }
    });

    // if we have an action select, wire up show_when logic
    if (actionSelect) {
      actionSelect.addEventListener("change", e => {
        const val = e.target.value;
        paramFields.querySelectorAll("div[data-show-when]").forEach(w => {
          w.style.display = (w.dataset.showWhen === val) ? "block" : "none";
        });
      });
      // trigger once to hide everything except action
      actionSelect.dispatchEvent(new Event("change"));
    }
  });

  // 5. Show spinner on submit
  document.getElementById("crypto-form").addEventListener("submit", () => {
    runBtn.disabled = true;
    runBtn.innerHTML = `
      <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
      Processing…`;
  });

  // 6. Copy output
  copyBtn.addEventListener("click", () => {
    const txt = outputPre.textContent.trim();
    if (!txt) return;
    navigator.clipboard.writeText(txt)
      .then(() => copyToast.show())
      .catch(console.error);
  });
});
