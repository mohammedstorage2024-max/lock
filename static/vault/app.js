document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-open]").forEach((button) => {
    button.addEventListener("click", () => document.getElementById(button.dataset.open)?.showModal());
  });
  document.querySelectorAll("dialog.modal").forEach((dialog) => {
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
  });
  const preview = document.getElementById("preview-dialog");
  const frame = document.getElementById("preview-frame");
  document.querySelectorAll("[data-preview-url]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      document.getElementById("preview-title").textContent = link.dataset.previewTitle;
      frame.src = link.dataset.previewUrl;
      preview.showModal();
    });
  });
  preview?.addEventListener("close", () => { frame.src = "about:blank"; });
  document.querySelectorAll(".alert").forEach((alert) => setTimeout(() => alert.classList.add("fade-away"), 4500));
});
