// Mapping of category values to their algorithms
const ALGOS = {
  symmetric: [
    { key: "caesar",   label: "Caesar Cipher"   },
    { key: "vigenere", label: "Vigenère Cipher" }
  ],
  asymmetric: [
    { key: "rsa", label: "RSA (2048-bit)" },
    { key: "ecc", label: "Elliptic Curve (P-256)" }
  ],
  signature: [
    { key: "rsa_sign", label: "RSA Signature" },
    { key: "ecdsa",    label: "ECDSA"         }
  ],
  hashing: [
    { key: "sha256",     label: "SHA-256"     },
    { key: "hmac_sha256", label: "HMAC-SHA256" }
  ]
};

document.addEventListener("DOMContentLoaded", () => {
  // Elements
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

  // 1. Initialize all Bootstrap tooltips
  document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
    new bootstrap.Tooltip(el);
  });

  // 2. Dark/Light mode toggle
  const storedTheme = localStorage.getItem("theme") || "light";
  htmlEl.setAttribute("data-theme", storedTheme);
  updateThemeIcon(storedTheme);

  themeBtn.addEventListener("click", () => {
    const current = htmlEl.getAttribute("data-theme");
    const next = current === "light" ? "dark" : "light";
    htmlEl.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
    updateThemeIcon(next);
  });

  function updateThemeIcon(theme) {
    themeIcon.className = theme === "light"
      ? "bi bi-moon-fill"
      : "bi bi-sun-fill";
  }

  // 3. Populate Algorithm dropdown when Category changes
  catSelect.addEventListener("change", () => {
    const cat = catSelect.value;
    algoSelect.innerHTML = `<option value="" disabled selected>Select algo…</option>`;

    if (ALGOS[cat]) {
      ALGOS[cat].forEach(({key, label}) => {
        const opt = document.createElement("option");
        opt.value = key;
        opt.textContent = label;
        algoSelect.append(opt);
      });
    }

    // Clear param fields and output
    paramFields.innerHTML = "";
    outputPre.textContent = "";
  });

  // 4. Show parameter inputs when Algorithm changes
  algoSelect.addEventListener("change", () => {
    const algo = algoSelect.value;
    paramFields.innerHTML = "";

    switch (algo) {
      case "caesar":
        paramFields.innerHTML = `
          <div class="mb-3">
            <label for="shift" class="form-label">Shift</label>
            <input type="number" class="form-control" id="shift" name="shift"
                   value="3" required>
          </div>`;
        break;

      case "vigenere":
        paramFields.innerHTML = `
          <div class="mb-3">
            <label for="key" class="form-label">Key</label>
            <input type="text" class="form-control" id="key" name="key"
                   placeholder="Enter keyword" required>
          </div>`;
        break;

      case "rsa":
      case "rsa_sign":
      case "ecc":
        paramFields.innerHTML = `
          <div class="mb-3">
            <label for="keysize" class="form-label">Key size (bits)</label>
            <select class="form-select" id="keysize" name="keysize">
              <option value="1024">1024</option>
              <option value="2048" selected>2048</option>
              <option value="3072">3072</option>
            </select>
          </div>`;
        break;

      case "sha256":
      case "hmac_sha256":
        // No extra parameters for hashing algorithms
        break;

      default:
        // For any future algorithms, leave blank
        break;
    }
  });

  // 5. Show spinner on form submit
  const form = document.getElementById("crypto-form");
  if (form) {
    form.addEventListener("submit", () => {
      runBtn.disabled = true;
      runBtn.innerHTML = `
        <span class="spinner-border spinner-border-sm" role="status"
              aria-hidden="true"></span> Processing…`;
    });
  }

  // 6. Copy-to-clipboard functionality
  copyBtn.addEventListener("click", () => {
    const text = outputPre.textContent.trim();
    if (!text) return;
    navigator.clipboard.writeText(text)
      .then(() => copyToast.show())
      .catch(err => console.error("Copy failed:", err));
  });
});
