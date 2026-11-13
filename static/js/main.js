// CyberGuard AI - small helpers used on every page

// 1. Open and close the sidebar on small screens
const menuBtn = document.getElementById("menuBtn");
const sidebar = document.getElementById("sidebar");
if (menuBtn && sidebar) {
  menuBtn.addEventListener("click", () => {
    const isOpen = sidebar.classList.toggle("open");
    menuBtn.setAttribute("aria-expanded", String(isOpen));
  });
}

// 2. Close a message box when the x button is clicked
document.querySelectorAll("[data-dismiss]").forEach((button) => {
  button.addEventListener("click", () => {
    button.closest(".flash").remove();
  });
});

// 3. Show or hide a password field
document.querySelectorAll("[data-toggle-password]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.togglePassword);
    const showing = input.type === "text";
    input.type = showing ? "password" : "text";
    button.textContent = showing ? "Show" : "Hide";
  });
});