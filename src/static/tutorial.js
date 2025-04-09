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
      <li><strong>Right-click</strong> on a node to open a context menu with options (e.g. expand children or parents).</li>
      <li><strong>Double-click</strong> on a node to expand its children.</li>
      <li><strong>Pause simulation:</strong> Hold <strong>Space</strong> or <strong>CTRL</strong> to pause the force simulation, then release to resume.</li>
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

// Show tutorial when the document content is loaded.
document.addEventListener("DOMContentLoaded", showTutorial);
