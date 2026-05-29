/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare const React: unknown;

const rotatingAgents = ["", "claude", "opencode", "codex"];

export function CommandTerminal({ command }: { command: string }) {
  return (
    <div
      style={{
        background: "#1a1a2e",
        borderRadius: "8px",
        boxShadow: "0 4px 16px rgb(0 0 0 / 25%)",
        fontFamily:
          '"SFMono-Regular", Menlo, Monaco, Consolas, "Liberation Mono", monospace',
        fontSize: "0.875rem",
        lineHeight: 1.8,
        margin: "1.5rem 0",
        overflow: "hidden",
      }}
    >
      <style>{`
        @keyframes nc-cycle {
          0%,
          20% {
            opacity: 1;
          }
          25%,
          100% {
            opacity: 0;
          }
        }

        @keyframes nc-blink {
          50% {
            opacity: 0;
          }
        }
      `}</style>
      <div
        style={{
          alignItems: "center",
          background: "#252545",
          display: "flex",
          gap: "7px",
          padding: "10px 14px",
        }}
      >
        <span style={dotStyle("#ff5f56")} />
        <span style={dotStyle("#ffbd2e")} />
        <span style={dotStyle("#27c93f")} />
      </div>
      <div
        style={{
          color: "#d4d4d8",
          display: "grid",
          gridTemplateRows: "repeat(2, 1.8em)",
          overflowX: "auto",
          padding: "16px 20px",
        }}
      >
        <div style={{ minWidth: "max-content", whiteSpace: "nowrap" }}>
          <span style={{ color: "#76B900", userSelect: "none" }}>$ </span>
          <span>{command}</span>
        </div>
        <div style={{ minWidth: "max-content", whiteSpace: "nowrap" }}>
          <span style={{ color: "#76B900", userSelect: "none" }}>$ </span>
          <span>{"openshell sandbox create "}</span>
          <span
            style={{
              display: "inline-block",
              height: "1.8em",
              minWidth: "12ch",
              overflow: "hidden",
              position: "relative",
              verticalAlign: "top",
            }}
          >
            {rotatingAgents.map((agent, index) => (
              <span
                key={agent}
                style={{
                  animation: "nc-cycle 12s ease-in-out infinite",
                  animationDelay: `${index * 3}s`,
                  inset: "0 auto auto 0",
                  opacity: 0,
                  position: "absolute",
                  whiteSpace: "nowrap",
                }}
              >
                {agent !== "" && (
                  <span>
                    {"-- "}
                    <span style={{ color: "#76B900", fontWeight: 600 }}>
                      {agent}
                    </span>
                    <span
                      style={{
                        animation: "nc-blink 1s step-end infinite",
                        background: "#d4d4d8",
                        display: "inline-block",
                        height: "1.1em",
                        marginLeft: "1px",
                        verticalAlign: "text-bottom",
                        width: "2px",
                      }}
                    />
                  </span>
                )}
              </span>
            ))}
          </span>
        </div>
      </div>
    </div>
  );
}

function dotStyle(background: string) {
  return {
    background,
    borderRadius: "50%",
    display: "inline-block",
    height: "12px",
    width: "12px",
  };
}
