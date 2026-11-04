export function scrollToSection(id: string): void {
  const el = document.getElementById(`section-${id}`);
  if (!el) return;
  el.scrollIntoView({ block: "start" });
  const heading = el.querySelector<HTMLElement>("h3, h2");
  if (heading) { heading.tabIndex = -1; heading.focus({ preventScroll: true }); }
}
