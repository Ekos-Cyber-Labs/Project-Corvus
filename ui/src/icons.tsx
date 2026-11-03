type P = { size?: number };
const S = ({ size = 16, children, viewBox = "0 0 24 24" }: P & { children: React.ReactNode; viewBox?: string }) => (
  <svg width={size} height={size} viewBox={viewBox} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">{children}</svg>
);
export const IconShield = (p: P) => (<S {...p}><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" /><path d="M9 12l2 2 4-4" /></S>);
export const IconClock = (p: P) => (<S {...p}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></S>);
export const IconAlert = (p: P) => (<S {...p}><path d="M12 3L2 20h20L12 3z" /><path d="M12 10v4M12 17.5v.5" /></S>);
export const IconHost = (p: P) => (<S {...p}><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></S>);
export const IconRule = (p: P) => (<S {...p}><path d="M5 4h14M5 9h14M5 14h9M5 19h6" /></S>);
export const IconCheck = (p: P) => (<S {...p}><path d="M4 12.5l5 5L20 6.5" /></S>);
export const IconCross = (p: P) => (<S {...p}><path d="M5 5l14 14M19 5L5 19" /></S>);
export const IconArrow = (p: P) => (<S {...p}><path d="M4 12h16M14 6l6 6-6 6" /></S>);
export const IconChevron = (p: P) => (<S {...p}><path d="M6 9l6 6 6-6" /></S>);
export const IconCopy = (p: P) => (<S {...p}><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V6a2 2 0 0 1 2-2h9" /></S>);
export const IconSpark = (p: P) => (<S {...p}><path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3z" /></S>);
export const IconDatabase = (p: P) => (<S {...p}><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5" /><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" /></S>);
