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

  // Enable Bootstrap tooltips
  document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
    new bootstrap.Tooltip(el);
  });

  // Initialize theme from localStorage and set up toggle button
  const storedTheme = localStorage.getItem("theme") || "light";
  htmlEl.setAttribute("data-theme", storedTheme);
  updateIcon(storedTheme);
  themeBtn.addEventListener("click", () => {
    const newTheme = htmlEl.getAttribute("data-theme") === "light" ? "dark" : "light";
    htmlEl.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);
    updateIcon(newTheme);
  });

  function updateIcon(theme) {
    // Switch between moon and sun icon
    themeIcon.className = theme === "light" ? "bi bi-moon-fill" : "bi bi-sun-fill";
  }

  // When the user selects a category, load its algorithms
  catSelect.addEventListener("change", () => {
    algoSelect.innerHTML = `<option value="" disabled selected>Select algorithm…</option>`;
    paramFields.innerHTML = "";
    outputPre.textContent = "";
    runBtn.disabled = false;

    (ALGOS[catSelect.value] || []).forEach(({key, label}) => {
      const option = document.createElement("option");
      option.value = key;
      option.textContent = label;
      algoSelect.append(option);
    });
  });

  // When the user picks an algorithm, render its input fields
  algoSelect.addEventListener("change", () => {
    paramFields.innerHTML = "";
    outputPre.textContent = "";

    const specs = ALGO_PARAMS[algoSelect.value] || [];
    let actionSelect = null;

    specs.forEach(spec => {
      const wrapper = document.createElement("div");
      wrapper.className = "mb-3";

      if (spec.show_when) {
        wrapper.style.display = "none";
        wrapper.dataset.showWhen = spec.show_when;
      }
      if (spec.show_when_mode) {
        wrapper.style.display = "none";
        wrapper.dataset.showWhenMode = spec.show_when_mode.join(",");
      }

      // Field label
      if (spec.label) {
        const label = document.createElement("label");
        label.htmlFor = spec.name;
        label.className = "form-label";
        label.textContent = spec.label;
        wrapper.append(label);
      }

      // Build input element
      let input;
      if (spec.type === "textarea") {
        input = document.createElement("textarea");
        input.className = "form-control";
        input.rows = spec.rows || 3;
      } else if (spec.type === "select") {
        input = document.createElement("select");
        input.className = "form-select";
        spec.options.forEach(opt => {
          const o = document.createElement("option");
          o.value = o.textContent = opt;
          input.append(o);
        });
      } else {
        input = document.createElement("input");
        input.type = spec.type;
        input.className = "form-control";
        if (spec.min != null)   input.min       = spec.min;
        if (spec.max != null)   input.max       = spec.max;
        if (spec.value != null) input.value     = spec.value;
      }

      // Common attributes
      input.id = spec.name;
      input.name = spec.name;
      if (spec.required)    input.required    = true;
      if (spec.placeholder) input.placeholder = spec.placeholder;
      if (spec.minlength != null) input.minLength = spec.minlength;
      if (spec.maxlength != null) input.maxLength = spec.maxlength;
      if (spec.pattern    != null) input.pattern   = spec.pattern;
      if (spec.title      != null) input.title     = spec.title;

      wrapper.append(input);
      paramFields.append(wrapper);

      if (spec.name === "action") {
        actionSelect = input;
      }
    });

    // Handle conditional fields based on action or mode
    if (actionSelect) {
      const modeSelect = paramFields.querySelector("select[name=mode]");
      if (modeSelect) {
        const updateModeVisibility = () => {
          const m = modeSelect.value;
          paramFields.querySelectorAll("[data-show-when-mode]").forEach(w => {
            w.style.display = w.dataset.showWhenMode.split(",").includes(m) ? "block" : "none";
          });
        };
        modeSelect.addEventListener("change", updateModeVisibility);
        updateModeVisibility();
      }

      // Track original required flags
      paramFields.querySelectorAll("[data-show-when]").forEach(wrapper => {
        const inp = wrapper.querySelector("input,textarea,select");
        wrapper.dataset.origReq = inp.required;
      });

      const updateActionVisibility = () => {
        const act = actionSelect.value;
        paramFields.querySelectorAll("[data-show-when]").forEach(wrapper => {
          const show = wrapper.dataset.showWhen === act;
          wrapper.style.display = show ? "block" : "none";
          const inp = wrapper.querySelector("input,textarea,select");
          inp.required = show && wrapper.dataset.origReq === "true";
        });
      };

      actionSelect.addEventListener("change", updateActionVisibility);
      updateActionVisibility();
    }
  });

  // Show a loading spinner while form is submitting
  document.getElementById("crypto-form").addEventListener("submit", () => {
    runBtn.disabled = true;
    runBtn.innerHTML = `
      <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
      Processing…`;
  });

  // Copy the output text to clipboard
  copyBtn.addEventListener("click", () => {
    const text = outputPre.textContent.trim();
    if (!text) return;
    navigator.clipboard.writeText(text)
      .then(() => copyToast.show())
      .catch(console.error);
  });
});
