import { useState, useEffect } from "react";

const SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club", ".online", ".site", ".info", ".biz"];
const PHISHING_KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "banking", "paypal", "amazon", "apple", "microsoft", "support", "confirm", "password", "credential", "wallet", "invoice", "suspended"];
const LEGITIMATE_DOMAINS = ["google.com", "facebook.com", "twitter.com", "amazon.com", "apple.com", "microsoft.com", "paypal.com", "instagram.com", "linkedin.com", "github.com"];

function analyzeURL(rawUrl) {
  const checks = [];
  let score = 0;
  let url = rawUrl.trim();
  if (!url.startsWith("http://") && !url.startsWith("https://"))
    url = "https://" + url;

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { error: "Invalid URL format." };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = url.toLowerCase();
  const path = (parsed.pathname + parsed.search).toLowerCase();

  // 1. HTTPS check
  if (parsed.protocol === "http:") {
    checks.push({ label: "No HTTPS (insecure protocol)", risk: "high", detail: "Uses HTTP instead of HTTPS — traffic can be intercepted." });
    score += 25;
  } else {
    checks.push({ label: "HTTPS in use", risk: "safe", detail: "Connection is encrypted." });
  }

  // 2. IP address as hostname
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipRegex.test(hostname)) {
    checks.push({ label: "IP address used instead of domain", risk: "high", detail: "Legitimate sites rarely use raw IPs." });
    score += 30;
  }

  // 3. Suspicious TLD
  const suspTLD = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t));
  if (suspTLD) {
    checks.push({ label: `Suspicious TLD detected: ${suspTLD}`, risk: "medium", detail: "Free or high-abuse TLDs are commonly used in phishing." });
    score += 20;
  }

  // 4. Lookalike domain (homoglyph-style check)
  const lookalike = LEGITIMATE_DOMAINS.find(legit => {
    const base = legit.split(".")[0];
    const hostBase = hostname.replace(/\.[^.]+$/, "").replace(/^www\./, "");
    return hostBase !== base && (hostBase.includes(base) || levenshtein(hostBase, base) <= 2);
  });
  if (lookalike) {
    checks.push({ label: `Possible lookalike of "${lookalike}"`, risk: "high", detail: "Domain closely resembles a trusted brand — common in spear-phishing." });
    score += 35;
  }

  // 5. Too many subdomains
  const parts = hostname.split(".");
  if (parts.length > 4) {
    checks.push({ label: `Excessive subdomains (${parts.length - 2} levels deep)`, risk: "medium", detail: "e.g. login.verify.paypal.attacker.com — attackers put legit names in subdomains." });
    score += 20;
  }

  // 6. Phishing keywords in URL
  const foundKw = PHISHING_KEYWORDS.filter(kw => fullUrl.includes(kw));
  if (foundKw.length >= 2) {
    checks.push({ label: `Multiple phishing keywords: ${foundKw.slice(0, 3).join(", ")}`, risk: "high", detail: "Stacking urgency/auth keywords is a major phishing indicator." });
    score += 25;
  } else if (foundKw.length === 1) {
    checks.push({ label: `Phishing keyword detected: "${foundKw[0]}"`, risk: "medium", detail: "Common in credential-harvesting pages." });
    score += 10;
  }

  // 7. Long URL
  if (fullUrl.length > 100) {
    checks.push({ label: `Very long URL (${fullUrl.length} chars)`, risk: "medium", detail: "Attackers use long URLs to obscure malicious parts." });
    score += 15;
  }

  // 8. Hyphens in domain
  const domainPart = hostname.split(".").slice(0, -1).join(".");
  const hyphenCount = (domainPart.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    checks.push({ label: `Many hyphens in domain (${hyphenCount})`, risk: "medium", detail: 'e.g. "paypal-secure-login-verify.com" — hyphens pad fake domains.' });
    score += 15;
  }

  // 9. @ symbol in URL
  if (fullUrl.includes("@")) {
    checks.push({ label: "@ symbol in URL", risk: "high", detail: "Everything before @ is ignored by browser — used to deceive users." });
    score += 30;
  }

  // 10. URL shortener
  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd", "buff.ly"];
  if (shorteners.some(s => hostname.includes(s))) {
    checks.push({ label: "URL shortener detected", risk: "medium", detail: "Hides the real destination. Always expand before clicking." });
    score += 15;
  }

  if (checks.filter(c => c.risk !== "safe").length === 0) {
    checks.push({ label: "No major red flags detected", risk: "safe", detail: "URL passed all heuristic checks. Still exercise caution." });
  }

  const clampedScore = Math.min(score, 100);
  let verdict, color;
  if (clampedScore >= 60) { verdict = "HIGH RISK"; color = "#ff4444"; }
  else if (clampedScore >= 30) { verdict = "SUSPICIOUS"; color = "#ffaa00"; }
  else { verdict = "LIKELY SAFE"; color = "#00e676"; }

  return { checks, score: clampedScore, verdict, color, hostname };
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

const RISK_CONFIG = {
  high:   { icon: "⬤", label: "HIGH",   bg: "rgba(255,68,68,0.12)",  border: "#ff4444", text: "#ff6666" },
  medium: { icon: "⬤", label: "MED",    bg: "rgba(255,170,0,0.12)",  border: "#ffaa00", text: "#ffcc44" },
  safe:   { icon: "⬤", label: "SAFE",   bg: "rgba(0,230,118,0.08)",  border: "#00e676", text: "#00e676" },
};

export default function PhishingDetector() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dots, setDots] = useState("");
  const [typed, setTyped] = useState("");
  const headline = "PHISHING URL DETECTOR";

  useEffect(() => {
    let i = 0;
    const t = setInterval(() => {
      setTyped(headline.slice(0, i + 1));
      i++;
      if (i >= headline.length) clearInterval(t);
    }, 55);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!loading) return;
    const t = setInterval(() => setDots(d => d.length >= 3 ? "" : d + "."), 350);
    return () => clearInterval(t);
  }, [loading]);

  const analyze = () => {
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    setTimeout(() => {
      setResult(analyzeURL(url));
      setLoading(false);
    }, 1200);
  };

  const arcPath = (pct) => {
    const r = 54, cx = 64, cy = 64;
    const angle = (pct / 100) * 270 - 135;
    const rad = (a) => (a * Math.PI) / 180;
    const x = cx + r * Math.cos(rad(angle));
    const y = cy + r * Math.sin(rad(angle));
    return { x, y };
  };

  const describeArc = (pct) => {
    const r = 54, cx = 64, cy = 64;
    const startAngle = -135, endAngle = startAngle + (pct / 100) * 270;
    const rad = (a) => (a * Math.PI) / 180;
    const x1 = cx + r * Math.cos(rad(startAngle));
    const y1 = cy + r * Math.sin(rad(startAngle));
    const x2 = cx + r * Math.cos(rad(endAngle));
    const y2 = cy + r * Math.sin(rad(endAngle));
    const large = (pct / 100) * 270 > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
  };

  return (
    <div style={{
      minHeight: "100vh", background: "#050810",
      fontFamily: "'Courier New', monospace",
      padding: "32px 16px",
      backgroundImage: "radial-gradient(ellipse at 20% 50%, rgba(0,100,255,0.04) 0%, transparent 60%), radial-gradient(ellipse at 80% 20%, rgba(255,0,100,0.04) 0%, transparent 60%)",
    }}>
      {/* Scanline overlay */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
        backgroundImage: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)",
      }} />

      <div style={{ maxWidth: 680, margin: "0 auto", position: "relative", zIndex: 1 }}>

        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <div style={{ fontSize: 11, letterSpacing: "0.3em", color: "#ff4444", marginBottom: 8, opacity: 0.8 }}>
            ▸ THREAT INTELLIGENCE SYSTEM v2.4
          </div>
          <h1 style={{
            fontSize: "clamp(20px, 5vw, 32px)", fontWeight: 900, letterSpacing: "0.15em",
            color: "#e8f0fe", margin: 0, textShadow: "0 0 30px rgba(100,160,255,0.3)",
          }}>
            {typed}<span style={{ animation: "blink 1s step-end infinite", color: "#4488ff" }}>█</span>
          </h1>
          <div style={{ height: 2, background: "linear-gradient(90deg, transparent, #4488ff, #ff4444, transparent)", marginTop: 12 }} />
        </div>

        {/* Input area */}
        <div style={{
          background: "rgba(10,20,40,0.8)", border: "1px solid rgba(68,136,255,0.25)",
          borderRadius: 4, padding: "20px 24px", marginBottom: 24,
          boxShadow: "0 0 40px rgba(68,136,255,0.05), inset 0 1px 0 rgba(255,255,255,0.03)",
        }}>
          <div style={{ fontSize: 10, color: "#4488ff", letterSpacing: "0.2em", marginBottom: 10 }}>
            TARGET URL
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <div style={{ flex: 1, display: "flex", alignItems: "center", background: "rgba(0,0,0,0.4)", border: "1px solid rgba(68,136,255,0.2)", borderRadius: 3, padding: "0 12px" }}>
              <span style={{ color: "#4488ff", fontSize: 13, marginRight: 8, opacity: 0.7 }}>⊞</span>
              <input
                value={url}
                onChange={e => setUrl(e.target.value)}
                onKeyDown={e => e.key === "Enter" && analyze()}
                placeholder="https://paypa1-secure-login.xyz/verify"
                style={{
                  flex: 1, background: "transparent", border: "none", outline: "none",
                  color: "#c8d8f0", fontSize: 13, padding: "12px 0", fontFamily: "inherit",
                  caretColor: "#4488ff",
                }}
              />
            </div>
            <button
              onClick={analyze}
              disabled={loading || !url.trim()}
              style={{
                background: loading ? "rgba(68,136,255,0.1)" : "rgba(68,136,255,0.15)",
                border: "1px solid rgba(68,136,255,0.4)",
                color: loading ? "#4466aa" : "#88bbff",
                padding: "12px 20px", borderRadius: 3, cursor: loading ? "default" : "pointer",
                fontFamily: "inherit", fontSize: 12, letterSpacing: "0.15em",
                fontWeight: 700, transition: "all 0.2s", whiteSpace: "nowrap",
              }}
            >
              {loading ? `SCANNING${dots}` : "▶ SCAN"}
            </button>
          </div>
          <div style={{ fontSize: 10, color: "#334466", marginTop: 10, letterSpacing: "0.1em" }}>
            HEURISTIC ANALYSIS — NO NETWORK REQUESTS MADE — CLIENT-SIDE ONLY
          </div>
        </div>

        {/* Loading bar */}
        {loading && (
          <div style={{ marginBottom: 24 }}>
            <div style={{ height: 2, background: "rgba(68,136,255,0.1)", borderRadius: 1, overflow: "hidden" }}>
              <div style={{
                height: "100%", background: "linear-gradient(90deg, #4488ff, #ff4444)",
                animation: "scan 1.2s ease-in-out forwards",
                width: "100%",
              }} />
            </div>
          </div>
        )}

        {/* Results */}
        {result && !result.error && (
          <div style={{ animation: "fadeIn 0.4s ease" }}>

            {/* Score gauge + verdict */}
            <div style={{
              display: "flex", gap: 20, marginBottom: 20,
              background: "rgba(10,20,40,0.8)", border: `1px solid ${result.color}33`,
              borderRadius: 4, padding: "24px",
              boxShadow: `0 0 40px ${result.color}11`,
            }}>
              {/* SVG Gauge */}
              <div style={{ flexShrink: 0 }}>
                <svg width={128} height={128} viewBox="0 0 128 128">
                  <path d={describeArc(100)} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" strokeLinecap="round"/>
                  <path d={describeArc(result.score)} fill="none" stroke={result.color} strokeWidth="8" strokeLinecap="round"
                    style={{ filter: `drop-shadow(0 0 6px ${result.color})`, transition: "stroke-dashoffset 1s" }}/>
                  <text x="64" y="60" textAnchor="middle" fill={result.color}
                    fontSize="22" fontWeight="900" fontFamily="Courier New">
                    {result.score}
                  </text>
                  <text x="64" y="76" textAnchor="middle" fill="rgba(255,255,255,0.3)" fontSize="8" fontFamily="Courier New" letterSpacing="2">
                    RISK SCORE
                  </text>
                </svg>
              </div>

              {/* Verdict text */}
              <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "center" }}>
                <div style={{ fontSize: 10, color: "#4466aa", letterSpacing: "0.2em", marginBottom: 6 }}>VERDICT</div>
                <div style={{ fontSize: 28, fontWeight: 900, color: result.color, letterSpacing: "0.1em", textShadow: `0 0 20px ${result.color}66` }}>
                  {result.verdict}
                </div>
                <div style={{ fontSize: 11, color: "#4488aa", marginTop: 8, wordBreak: "break-all" }}>
                  {result.hostname}
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
                  {["high", "medium"].map(level => {
                    const count = result.checks.filter(c => c.risk === level).length;
                    if (!count) return null;
                    const cfg = RISK_CONFIG[level];
                    return (
                      <span key={level} style={{ fontSize: 10, padding: "3px 8px", borderRadius: 2, background: cfg.bg, border: `1px solid ${cfg.border}44`, color: cfg.text, letterSpacing: "0.1em" }}>
                        {count} {cfg.label} RISK
                      </span>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Checks list */}
            <div style={{ background: "rgba(10,20,40,0.8)", border: "1px solid rgba(68,136,255,0.15)", borderRadius: 4, overflow: "hidden" }}>
              <div style={{ padding: "10px 20px", borderBottom: "1px solid rgba(68,136,255,0.1)", fontSize: 10, color: "#4488ff", letterSpacing: "0.2em" }}>
                INDICATOR ANALYSIS — {result.checks.length} CHECKS
              </div>
              {result.checks.map((c, i) => {
                const cfg = RISK_CONFIG[c.risk] || RISK_CONFIG.safe;
                return (
                  <div key={i} style={{
                    display: "flex", gap: 14, padding: "14px 20px",
                    borderBottom: i < result.checks.length - 1 ? "1px solid rgba(255,255,255,0.03)" : "none",
                    background: i % 2 === 0 ? "rgba(0,0,0,0.2)" : "transparent",
                    alignItems: "flex-start",
                  }}>
                    <span style={{ color: cfg.text, fontSize: 8, marginTop: 4, flexShrink: 0 }}>⬤</span>
                    <div>
                      <div style={{ fontSize: 12, color: cfg.text, fontWeight: 700, marginBottom: 3 }}>{c.label}</div>
                      <div style={{ fontSize: 11, color: "#4466aa", lineHeight: 1.5 }}>{c.detail}</div>
                    </div>
                    <span style={{ marginLeft: "auto", fontSize: 9, padding: "2px 6px", borderRadius: 2, background: cfg.bg, border: `1px solid ${cfg.border}33`, color: cfg.text, flexShrink: 0 }}>
                      {cfg.label}
                    </span>
                  </div>
                );
              })}
            </div>

            {/* Footer note */}
            <div style={{ fontSize: 10, color: "#223344", textAlign: "center", marginTop: 16, letterSpacing: "0.1em" }}>
              ⚠ HEURISTIC ANALYSIS ONLY — ALWAYS VERIFY WITH THREAT INTELLIGENCE FEEDS IN PRODUCTION
            </div>
          </div>
        )}

        {result?.error && (
          <div style={{ padding: 16, background: "rgba(255,68,68,0.08)", border: "1px solid rgba(255,68,68,0.3)", borderRadius: 4, color: "#ff6666", fontSize: 13 }}>
            ✕ {result.error}
          </div>
        )}

        {/* Example URLs */}
        {!result && !loading && (
          <div style={{ marginTop: 8 }}>
            <div style={{ fontSize: 10, color: "#334466", letterSpacing: "0.15em", marginBottom: 10 }}>TRY THESE EXAMPLES</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {[
                "http://paypa1-secure-login.xyz/verify/account",
                "https://login.verify.amazon.support-check.com",
                "https://bit.ly/3xK9mPf",
                "https://github.com/login",
              ].map(ex => (
                <button key={ex} onClick={() => setUrl(ex)} style={{
                  background: "rgba(68,136,255,0.05)", border: "1px solid rgba(68,136,255,0.1)",
                  color: "#4466aa", padding: "8px 14px", borderRadius: 3, cursor: "pointer",
                  fontFamily: "inherit", fontSize: 11, textAlign: "left", transition: "all 0.15s",
                  letterSpacing: "0.05em",
                }}
                  onMouseEnter={e => { e.target.style.borderColor = "rgba(68,136,255,0.35)"; e.target.style.color = "#6688cc"; }}
                  onMouseLeave={e => { e.target.style.borderColor = "rgba(68,136,255,0.1)"; e.target.style.color = "#4466aa"; }}
                >
                  ▸ {ex}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      <style>{`
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes scan { from{width:0} to{width:100%} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
        input::placeholder { color: #2a3a5a; }
      `}</style>
    </div>
  );
}