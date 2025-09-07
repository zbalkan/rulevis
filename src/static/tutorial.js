// Cookie utility functions
function getCookie(name) {
  const value = "; " + document.cookie;
  const parts = value.split("; " + name + "=");
  if (parts.length >= 2) return parts.pop().split(";").shift();
  return null;
}

function setCookie(name, value, days) {
  let expires = "";
  if (days) {
    const date = new Date();
    date.setTime(date.getTime() + days * 24 * 60 * 60 * 1000);
    expires = "; expires=" + date.toUTCString();
  }
  document.cookie = name + "=" + (value || "") + expires + "; path=/";
}

// Tutorial Modal Function
function showTutorial() {
  const overlay = document.createElement("div");
  overlay.id = "tutorialOverlay";
  overlay.style.cssText = `
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        background: rgba(0, 0, 0, 0.8);
        z-index: 2000;
        display: flex;
        align-items: center;
        justify-content: center;
    `;

  const messageBox = document.createElement("div");
  messageBox.id = "tutorialMessageBox";
  messageBox.style.cssText = `
        background: #333;
        color: #eee;
        padding: 20px;
        border-radius: 8px;
        width: 80%;
        max-width: 600px;
        text-align: left;
        font-family: 'Segoe UI', 'DejaVu Sans', Arial, sans-serif;
    `;

  messageBox.innerHTML = `
        <h2>Welcome to Rule Graph Explorer</h2>
        <p>This tool allows you to visualize rules as nodes in a graph.</p>
        <ul>
          <li><strong>Nodes:</strong> Represent individual rules.
            <ul>
              <li><span class="node-expandable" style="display:inline-block;width:12px;height:12px;border-radius:50%;background:steelblue;margin-right:4px;"></span>
                  Expandable (has children)</li>
              <li><span class="node-default" style="display:inline-block;width:12px;height:12px;border-radius:50%;background:grey;margin-right:4px;"></span>
                  Default (leaf node)</li>
            </ul>
          </li>
          <li><strong>Search: </strong>Search rules by rule ID and dislay in the graph.</li>
          <li><strong>Details panel: </strong>Shows details about the selected rule. You can access parent and child rules.</li>
          <li><strong>Heatmap: </strong>Shows the rule ID blocks of 10 to show the usable spaces.</li>
          <li><strong>Stats: </strong>Shows statistics about the parsed rules.</li>
          <li><strong>Pause simulation:</strong> Hold <strong>Space</strong> to pause the force simulation, then release to resume.</li>
          <li><strong>Warning:</strong> Expanding too many nodes may make the graph complex and slow down the simulation.</li>
        </ul>
        <button id="tutorialCloseButton" style="padding:8px 16px;border:none;border-radius:4px;background:#444;color:#eee;cursor:pointer;">
          Got it
        </button>
    `;

  overlay.appendChild(messageBox);
  document.body.appendChild(overlay);

  document.getElementById("tutorialCloseButton").addEventListener("click", () => {
    overlay.parentNode.removeChild(overlay);
  });
}

// Show tutorial only if not already shown in this session.
document.addEventListener("DOMContentLoaded", () => {
  if (!getCookie("tutorialShown")) {
    showTutorial();
    // Set a session cookie by not providing the days parameter.
    setCookie("tutorialShown", "1");
  }
});
