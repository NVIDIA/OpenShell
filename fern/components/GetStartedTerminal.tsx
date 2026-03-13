/**
 * Animated terminal block for the Get Started section.
 * Renders install + sandbox create commands with cycling agent options.
 */
export function GetStartedTerminal() {
  return (
    <>
      <style>{`
        .nc-term {
          background: #1a1a2e;
          border-radius: 8px;
          overflow: hidden;
          margin: 1.5em 0;
          box-shadow: 0 4px 16px rgba(0,0,0,0.25);
          font-family: 'SFMono-Regular', Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
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
        .nc-term-dot { width: 12px; height: 12px; border-radius: 50%; }
        .nc-term-dot-r { background: #ff5f56; }
        .nc-term-dot-y { background: #ffbd2e; }
        .nc-term-dot-g { background: #27c93f; }
        .nc-term-body { padding: 16px 20px; color: #d4d4d8; }
        .nc-term-body .nc-ps { color: #76b900; user-select: none; }
        .nc-swap {
          display: inline-grid;
          vertical-align: baseline;
        }
        .nc-swap > span {
          grid-area: 1 / 1;
          white-space: nowrap;
          opacity: 0;
          animation: nc-cycle 12s ease-in-out infinite;
        }
        .nc-swap > span:nth-child(2) { animation-delay: 3s; }
        .nc-swap > span:nth-child(3) { animation-delay: 6s; }
        .nc-swap > span:nth-child(4) { animation-delay: 9s; }
        @keyframes nc-cycle {
          0%, 3%     { opacity: 0; }
          5%, 20%    { opacity: 1; }
          25%, 100%  { opacity: 0; }
        }
        .nc-hl { color: #76b900; font-weight: 600; }
        .nc-cursor {
          display: inline-block;
          width: 2px;
          height: 1.1em;
          background: #d4d4d8;
          vertical-align: text-bottom;
          margin-left: 1px;
          animation: nc-blink 1s step-end infinite;
        }
        @keyframes nc-blink { 50% { opacity: 0; } }
      `}</style>
      <div className="nc-term">
        <div className="nc-term-bar">
          <span className="nc-term-dot nc-term-dot-r" />
          <span className="nc-term-dot nc-term-dot-y" />
          <span className="nc-term-dot nc-term-dot-g" />
        </div>
        <div className="nc-term-body">
          <div>
            <span className="nc-ps">$ </span>uv pip install openshell
          </div>
          <div>
            <span className="nc-ps">$ </span>openshell sandbox create{" "}
            <span className="nc-swap">
              <span>-- <span className="nc-hl">claude</span></span>
              <span>--from <span className="nc-hl">openclaw</span></span>
              <span>-- <span className="nc-hl">opencode</span></span>
              <span>-- <span className="nc-hl">codex</span></span>
            </span>
            <span className="nc-cursor" />
          </div>
        </div>
      </div>
    </>
  );
}
