// Icons drawn for Last Keys on a 24×24 grid (stroke icons, no dependency).

import type { SVGProps } from "react";

const paths = {
  lock: (
    <>
      <rect x="4.5" y="10.5" width="15" height="10" rx="2.5" />
      <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
      <path d="M12 14.5v2" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="M10.85 12.15 19 4" />
      <path d="m16 7 2.5 2.5" />
      <path d="m13.5 9.5 2 2" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m20 20-4.2-4.2" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
  star: (
    <path d="m12 3.8 2.45 4.97 5.48.8-3.96 3.86.93 5.46L12 16.31l-4.9 2.58.93-5.46-3.96-3.86 5.48-.8z" />
  ),
  copy: (
    <>
      <rect x="8.5" y="8.5" width="11" height="11" rx="2.5" />
      <path d="M15.5 8.5V6.5a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2" />
    </>
  ),
  eye: (
    <>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  eyeOff: (
    <>
      <path d="M9.9 5.7A9.7 9.7 0 0 1 12 5.5C18 5.5 21.5 12 21.5 12a17 17 0 0 1-2.7 3.5M6.4 6.9C3.9 8.6 2.5 12 2.5 12S6 18.5 12 18.5c1.6 0 3-.4 4.2-1" />
      <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
      <path d="m3.5 3.5 17 17" />
    </>
  ),
  edit: (
    <>
      <path d="M4 20h4L19 9a2.83 2.83 0 0 0-4-4L4 16z" />
      <path d="m13.5 6.5 4 4" />
    </>
  ),
  trash: (
    <>
      <path d="M4.5 7h15" />
      <path d="M9.5 7V5a1.5 1.5 0 0 1 1.5-1.5h2A1.5 1.5 0 0 1 14.5 5v2" />
      <path d="M6.5 7l.8 11.2A2 2 0 0 0 9.3 20h5.4a2 2 0 0 0 2-1.8L17.5 7" />
      <path d="M10 11v5M14 11v5" />
    </>
  ),
  globe: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M3.5 12h17" />
      <path d="M12 3.5c2.4 2.3 3.6 5.2 3.6 8.5s-1.2 6.2-3.6 8.5c-2.4-2.3-3.6-5.2-3.6-8.5S9.6 5.8 12 3.5z" />
    </>
  ),
  note: (
    <>
      <path d="M6.5 3.5h7l4 4v11a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2v-13a2 2 0 0 1 2-2z" />
      <path d="M13.5 3.5v4h4" />
      <path d="M8.5 12.5h7M8.5 16h5" />
    </>
  ),
  card: (
    <>
      <rect x="3" y="5.5" width="18" height="13" rx="2.5" />
      <path d="M3 10h18" />
      <path d="M7 15h3" />
    </>
  ),
  identity: (
    <>
      <circle cx="12" cy="8.5" r="3.8" />
      <path d="M4.5 20c.9-3.6 3.9-5.8 7.5-5.8s6.6 2.2 7.5 5.8" />
    </>
  ),
  grid: (
    <>
      <rect x="4" y="4" width="6.5" height="6.5" rx="1.8" />
      <rect x="13.5" y="4" width="6.5" height="6.5" rx="1.8" />
      <rect x="4" y="13.5" width="6.5" height="6.5" rx="1.8" />
      <rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.8" />
    </>
  ),
  sync: (
    <>
      <path d="M19.5 12a7.5 7.5 0 0 1-12.8 5.3" />
      <path d="M4.5 12A7.5 7.5 0 0 1 17.3 6.7" />
      <path d="M17.5 3v4h-4" />
      <path d="M6.5 21v-4h4" />
    </>
  ),
  settings: (
    <>
      <path d="M4 7h9M17 7h3M4 17h3M11 17h9" />
      <circle cx="15" cy="7" r="2.2" />
      <circle cx="9" cy="17" r="2.2" />
    </>
  ),
  devices: (
    <>
      <rect x="2.5" y="4.5" width="14" height="10" rx="2" />
      <path d="M6.5 18.5h6" />
      <rect x="15.5" y="9" width="6" height="11" rx="1.8" />
    </>
  ),
  shield: (
    <>
      <path d="M12 3.5 19 6v5.5c0 4.4-2.9 7.7-7 9-4.1-1.3-7-4.6-7-9V6z" />
      <path d="m9 12 2.2 2.2L15.5 10" />
    </>
  ),
  wand: (
    <>
      <path d="m5 19 9.5-9.5" />
      <path d="m13 8 3-3 3 3-3 3z" />
      <path d="M8 3.5v3M6.5 5h3M19 14.5v3M17.5 16h3" />
    </>
  ),
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  close: <path d="M6 6l12 12M18 6 6 18" />,
  alert: (
    <>
      <path d="M10.3 4.3 2.9 17.2A2 2 0 0 0 4.6 20h14.8a2 2 0 0 0 1.7-2.8L13.7 4.3a2 2 0 0 0-3.4 0z" />
      <path d="M12 9.5v4" />
      <path d="M12 16.8v.2" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5" />
      <path d="M12 7.8v.2" />
    </>
  ),
  chevronDown: <path d="m6.5 9.5 5.5 5.5 5.5-5.5" />,
  arrowLeft: <path d="M19 12H5m6-6-6 6 6 6" />,
  laptop: (
    <>
      <rect x="4.5" y="5" width="15" height="10" rx="1.8" />
      <path d="M2.5 19h19" />
    </>
  ),
  phone: (
    <>
      <rect x="7" y="3" width="10" height="18" rx="2.5" />
      <path d="M11 17.5h2" />
    </>
  ),
  terminal: (
    <>
      <rect x="3" y="4.5" width="18" height="15" rx="2.5" />
      <path d="m7.5 9.5 3 2.5-3 2.5M12.5 15h4" />
    </>
  ),
  cloud: (
    <path d="M7 18.5a4.5 4.5 0 0 1-.6-8.96A6 6 0 0 1 18 9.5a4.5 4.5 0 0 1-.5 9z" />
  ),
  history: (
    <>
      <path d="M4 12a8 8 0 1 0 2.4-5.7" />
      <path d="M4 4.5v3.8h3.8" />
      <path d="M12 8v4.5l3 1.8" />
    </>
  ),
  restore: (
    <>
      <path d="M9 14 4 9l5-5" />
      <path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11" />
    </>
  ),
  dice: (
    <>
      <rect x="4" y="4" width="16" height="16" rx="3.5" />
      <circle cx="8.8" cy="8.8" r="0.9" fill="currentColor" />
      <circle cx="15.2" cy="15.2" r="0.9" fill="currentColor" />
      <circle cx="12" cy="12" r="0.9" fill="currentColor" />
    </>
  ),
  link: (
    <>
      <path d="M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1" />
      <path d="M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1" />
    </>
  ),
} as const;

export type IconName = keyof typeof paths;

export function Icon({
  name,
  filled = false,
  ...props
}: { name: IconName; filled?: boolean } & SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill={filled ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      {paths[name]}
    </svg>
  );
}

export function Logo({ className = "logo" }: { className?: string }) {
  return (
    <svg className={className} viewBox="64 64 896 896" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="lk-logo-bg" x1="0.1" y1="0" x2="0.9" y2="1">
          <stop offset="0" stopColor="#4F46E5" />
          <stop offset="1" stopColor="#7C3AED" />
        </linearGradient>
        <linearGradient id="lk-logo-shine" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#FFFFFF" stopOpacity="0.18" />
          <stop offset="0.55" stopColor="#FFFFFF" stopOpacity="0" />
        </linearGradient>
      </defs>
      <rect x="64" y="64" width="896" height="896" rx="208" fill="url(#lk-logo-bg)" />
      <rect x="64" y="64" width="896" height="896" rx="208" fill="url(#lk-logo-shine)" />
      <g transform="translate(512 512) rotate(-40) translate(-512 -512)" fill="#FFFFFF">
        <path
          fillRule="evenodd"
          d="M512 214a168 168 0 1 1 0 336a168 168 0 1 1 0-336zm0 102a66 66 0 1 0 0 132a66 66 0 1 0 0-132z"
        />
        <rect x="474" y="520" width="76" height="318" rx="24" />
        <rect x="500" y="700" width="134" height="60" rx="18" />
        <rect x="500" y="786" width="102" height="52" rx="18" />
      </g>
    </svg>
  );
}
