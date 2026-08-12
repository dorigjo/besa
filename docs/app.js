// Besa static site behaviour. No dependencies, no trackers, no network calls.
// All translatable nodes carry data-en / data-de and hold plain text only, so
// textContent swaps never clobber sibling elements (e.g. the SECURITY.md link).
(function () {
  "use strict";

  var INSTALL_CMD = "npm install @dorigjo/besa";
  var currentLang = "en";

  function setLang(lang) {
    var normalized = lang === "de" ? "de" : "en";
    currentLang = normalized;
    document.documentElement.lang = normalized;

    var nodes = document.querySelectorAll("[data-en]");
    for (var i = 0; i < nodes.length; i += 1) {
      var el = nodes[i];
      var next = normalized === "de" ? el.getAttribute("data-de") : el.getAttribute("data-en");
      if (next !== null) {
        el.textContent = next;
      }
    }

    var enBtn = document.getElementById("btn-en");
    var deBtn = document.getElementById("btn-de");
    if (enBtn && deBtn) {
      var isDe = normalized === "de";
      enBtn.classList.toggle("active", !isDe);
      deBtn.classList.toggle("active", isDe);
      enBtn.setAttribute("aria-pressed", String(!isDe));
      deBtn.setAttribute("aria-pressed", String(isDe));
    }
  }

  function copyInstall(el) {
    if (!navigator.clipboard) {
      return;
    }
    navigator.clipboard
      .writeText(INSTALL_CMD)
      .then(function () {
        el.classList.add("copied");
        window.setTimeout(function () {
          el.classList.remove("copied");
        }, 1800);
        var status = document.getElementById("copy-status");
        if (status) {
          status.textContent =
            currentLang === "de" ? "In die Zwischenablage kopiert." : "Copied to clipboard.";
        }
      })
      .catch(function () {
        /* clipboard denied — no-op, command stays visible */
      });
  }

  function wireLanguageToggle() {
    var enBtn = document.getElementById("btn-en");
    var deBtn = document.getElementById("btn-de");
    if (enBtn) {
      enBtn.addEventListener("click", function () {
        setLang("en");
      });
    }
    if (deBtn) {
      deBtn.addEventListener("click", function () {
        setLang("de");
      });
    }
  }

  function wireCopyCommand() {
    var cmd = document.getElementById("install-cmd");
    if (!cmd) {
      return;
    }
    cmd.addEventListener("click", function () {
      copyInstall(cmd);
    });
    cmd.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        copyInstall(cmd);
      }
    });
  }

  function wireScrollReveal() {
    var revealables = document.querySelectorAll(".reveal");
    if (!("IntersectionObserver" in window)) {
      for (var i = 0; i < revealables.length; i += 1) {
        revealables[i].classList.add("visible");
      }
      return;
    }
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.08 },
    );
    for (var j = 0; j < revealables.length; j += 1) {
      observer.observe(revealables[j]);
    }
  }

  function init() {
    wireLanguageToggle();
    wireCopyCommand();
    wireScrollReveal();

    var preferred =
      navigator.language && navigator.language.indexOf("de") === 0 ? "de" : "en";
    setLang(preferred);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
