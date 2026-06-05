/**
 * Badge links for GitHub, License, PyPI, etc.
 * Uses a flex wrapper to display badges horizontally and hides Fern's
 * external-link icon that otherwise stacks under each badge image.
 * Requires the `.badge-links` CSS rule from main.css.
 */
export type BadgeItem = {
  href: string;
  src: string;
  alt: string;
};

const landingStyles = `
.badge-links .fern-mdx-link svg {
  display: none;
}
.badge-links + p {
  margin-top: 0 !important;
}
.boxed-tabs {
  margin-top: 0.75rem;
  margin-bottom: 1.25rem;
}
.boxed-tabs [role="tabpanel"] {
  margin-top: 0.2rem;
  padding: 0.625rem 0.875rem 0.875rem;
  border: 1px solid var(--border, var(--grayscale-a5));
  border-radius: 14px;
  background-color: #fcfcfa;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}
.boxed-tabs [role="tabpanel"] > :first-child {
  margin-top: 0 !important;
}
.boxed-tabs [role="tabpanel"] > :last-child {
  margin-bottom: 0 !important;
}
.boxed-tabs [role="tabpanel"] > .not-prose {
  margin-top: 0.5rem !important;
  margin-bottom: 0.75rem !important;
}
.dark .boxed-tabs [role="tabpanel"],
html[data-theme=dark] .boxed-tabs [role="tabpanel"] {
  background-color: var(--nv-dark-grey-2);
  box-shadow: none;
}
.explore-cards .fern-card {
  display: flex;
  height: 100%;
}
.explore-cards .fern-card > div,
.explore-cards .fern-card > div > div {
  display: flex;
  flex: 1 1 auto;
  flex-direction: column;
  width: 100%;
}
.explore-cards .fern-card p {
  margin-bottom: 0.75rem;
}
.explore-cards .fern-card .fern-docs-badge {
  align-self: flex-start;
  margin-top: auto;
}
.explore-cards .fern-card br {
  display: none;
}
.nc-term {
  background: #1a1a2e;
  border-radius: 8px;
  overflow: hidden;
  margin: 1.5em 0;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
  font-family: "SFMono-Regular", Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  font-size: 0.875em;
  line-height: 1.8;
}
.nc-term-bar {
  background: #252545;
  padding: 10px 14px;
  display: flex;
  gap: 7px;
  align-items: center;
}
.nc-term-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}
.nc-term-dot-r {
  background: #ff5f56;
}
.nc-term-dot-y {
  background: #ffbd2e;
}
.nc-term-dot-g {
  background: #27c93f;
}
.nc-term-body {
  display: grid;
  grid-template-rows: repeat(2, 1.8em);
  padding: 16px 20px;
  color: #d4d4d8;
  overflow-x: auto;
}
.nc-term-body > div {
  min-width: max-content;
  white-space: nowrap;
}
.nc-term-body .nc-ps {
  color: #76b900;
  user-select: none;
}
.nc-swap {
  display: inline-block;
  position: relative;
  min-width: 12ch;
  height: 1.8em;
  overflow: hidden;
  vertical-align: top;
}
.nc-swap > span {
  position: absolute;
  inset: 0 auto auto 0;
  white-space: nowrap;
  opacity: 0;
  animation: nc-cycle 12s ease-in-out infinite;
}
.nc-swap > span:nth-child(2) {
  animation-delay: 3s;
}
.nc-swap > span:nth-child(3) {
  animation-delay: 6s;
}
.nc-swap > span:nth-child(4) {
  animation-delay: 9s;
}
@keyframes nc-cycle {
  0%,
  3% {
    opacity: 0;
  }
  5%,
  20% {
    opacity: 1;
  }
  25%,
  100% {
    opacity: 0;
  }
}
.nc-hl {
  color: #76b900;
  font-weight: 600;
}
.nc-cursor {
  display: inline-block;
  width: 2px;
  height: 1.1em;
  background: #d4d4d8;
  vertical-align: text-bottom;
  margin-left: 1px;
  animation: nc-blink 1s step-end infinite;
}
@keyframes nc-blink {
  50% {
    opacity: 0;
  }
}
`;

export function BadgeLinks({ badges = [] }: { badges?: BadgeItem[] }) {
  if (badges.length === 0) {
    return null;
  }
  return (
    <>
      <style>{landingStyles}</style>
      <div
        className="badge-links"
        style={{
          alignItems: "center",
          display: "flex",
          flexWrap: "wrap",
          gap: "8px",
          lineHeight: 0,
          margin: "0.25rem 0 0.75rem",
        }}
      >
        {badges.map((b) => (
          <a
            key={b.href}
            href={b.href}
            target="_blank"
            rel="noreferrer"
            style={{
              alignItems: "center",
              display: "inline-flex",
              width: "auto",
            }}
          >
            <img
              src={b.src}
              alt={b.alt}
              style={{
                display: "block",
                margin: 0,
              }}
            />
          </a>
        ))}
      </div>
    </>
  );
}
