"use strict";

// Loaded in <head>, before the stylesheet paints anything, so the page never
// flashes the wrong theme. An external file because the CSP allows no inline
// script. A choice made with the button wins; until then the system decides.
(function () {
  var choice = null;
  try {
    choice = localStorage.getItem("secaudit.theme");
  } catch (_) {
    // storage blocked: fall through to the system preference
  }
  if (choice !== "light" && choice !== "dark") {
    choice = window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark" : "light";
  }
  document.documentElement.dataset.theme = choice;
})();
