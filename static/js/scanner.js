// CyberGuard AI - scanner pages: example buttons and a loading state

const scanForm = document.getElementById("scanForm");
const scanInput = document.getElementById("scanInput");

if (scanForm && scanInput) {
  // The example buttons only fill the box. They do not open or send anything.
  document.querySelectorAll("[data-example], [data-example-from]").forEach((button) => {
    button.addEventListener("click", () => {
      let text = button.dataset.example || "";
      if (button.dataset.exampleFrom) {
        // Longer examples (emails) are kept in a hidden text block on the page
        const source = document.getElementById(button.dataset.exampleFrom);
        text = source ? source.textContent.trim() : "";
      }
      scanInput.value = text;
      scanInput.focus();
    });
  });

  // Stop double clicks and show that something is happening
  scanForm.addEventListener("submit", () => {
    const submitButton = scanForm.querySelector("button[type=submit]");
    submitButton.disabled = true;
    submitButton.textContent = "Checking...";
  });
}