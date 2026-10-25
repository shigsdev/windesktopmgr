// Architecture tab -- split out of app.js (backlog #72). Classic script: shares globals; load order is in templates/index.html.
function loadArchitecture() {
  const iframe = document.getElementById("arch-iframe");
  iframe.src = "/architecture.html";
  // Auto-resize iframe to fit content
  iframe.onload = function() {
    try {
      const h = iframe.contentDocument.documentElement.scrollHeight;
      iframe.style.height = (h + 40) + "px";
    } catch(e) {
      iframe.style.height = "2400px";
    }
  };
}

