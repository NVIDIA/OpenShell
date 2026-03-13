/**
 * Badge links for GitHub, License, PyPI, etc.
 * Uses a custom wrapper to avoid Fern's external-link icon stacking under badges.
 */
export type BadgeItem = {
  href: string;
  src: string;
  alt: string;
};

const DEFAULT_BADGES: BadgeItem[] = [
  {
    href: "https://github.com/NVIDIA/OpenShell",
    src: "https://img.shields.io/badge/github-repo-green?logo=github",
    alt: "GitHub",
  },
  {
    href: "https://github.com/NVIDIA/OpenShell/blob/main/LICENSE",
    src: "https://img.shields.io/badge/License-Apache_2.0-blue",
    alt: "License",
  },
  {
    href: "https://pypi.org/project/openshell/",
    src: "https://img.shields.io/badge/PyPI-openshell-orange?logo=pypi",
    alt: "PyPI",
  },
];

export function BadgeLinks({ badges = DEFAULT_BADGES }: { badges?: BadgeItem[] }) {
  return (
    <div
      className="badge-links"
      style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}
    >
      {badges.map((b) => (
        <a key={b.href} href={b.href} target="_blank" rel="noreferrer">
          <img src={b.src} alt={b.alt} />
        </a>
      ))}
    </div>
  );
}
