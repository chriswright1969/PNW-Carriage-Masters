(() => {
  const main = document.getElementById("galleryMain");
  const strip = document.getElementById("galleryStrip");
  if (!main || !strip) return;

  strip.addEventListener("click", (e) => {
    const btn = e.target.closest("button.gthumb");
    if (!btn) return;

    const src = btn.getAttribute("data-src");
    const alt = btn.getAttribute("data-alt") || "Gallery image";
    if (!src) return;

    main.src = src;
    main.alt = alt;

    strip.querySelectorAll("button.gthumb").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");

    // keep selected thumb visible
    btn.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
  });
})();
