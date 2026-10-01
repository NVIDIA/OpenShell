<?xml version="1.0" encoding="UTF-8"?>
<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!--
  Convert a nextest JUnit report into a standalone HTML report (XSLT 1.0).

  Usage:
    xsltproc junit-to-html.xsl report.xml > report.html
    xsltproc -stringparam title "my suite report" junit-to-html.xsl report.xml > report.html

  Renders a summary plus a per-suite table with pass/fail/skip rows. The report
  heading is the `title` parameter (default "Test report").
-->
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" indent="yes" encoding="UTF-8"
      doctype-system="about:legacy-compat"/>

  <!-- Report heading; override via the xsltproc `title` string parameter. -->
  <xsl:param name="title" select="'Test report'"/>

  <xsl:template match="/testsuites">
    <html lang="en">
      <head>
        <meta charset="UTF-8"/>
        <title><xsl:value-of select="$title"/></title>
        <style>
          :root {
            --bg: #f6f7f9; --card: #fff; --ink: #1f2328; --muted: #656d76;
            --border: #d7dbe0; --pass: #1a7f37; --fail: #cf222e; --skip: #9a6700;
            --pass-bg: #eafbe7; --fail-bg: #fbecec; --skip-bg: #fdf6e3;
            --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
          }
          * { box-sizing: border-box; }
          body {
            font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
            margin: 0; padding: 2rem clamp(1rem, 4vw, 3rem); color: var(--ink);
            background: var(--bg); line-height: 1.45;
          }
          h1 { font-size: 1.5rem; margin: 0 0 1rem; }
          h2 {
            font-family: var(--mono); font-size: 0.95rem; font-weight: 600;
            margin: 2rem 0 0; color: var(--ink);
          }
          h2 .count { color: var(--muted); font-weight: 400; }

          .summary { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 0 0 0.5rem; }
          .summary .card {
            background: var(--card); border: 1px solid var(--border); border-radius: 8px;
            padding: 0.5rem 0.9rem; min-width: 5.5rem;
          }
          .summary .card .label {
            display: block; font-size: 0.7rem; text-transform: uppercase;
            letter-spacing: 0.04em; color: var(--muted);
          }
          .summary .card .value { font-size: 1.35rem; font-weight: 700; }
          .card.c-fail .value { color: var(--fail); }
          .card.c-skip .value { color: var(--skip); }
          .card.c-fail.zero .value, .card.c-skip.zero .value { color: var(--muted); }

          table {
            border-collapse: collapse; width: 100%; margin-top: 0.6rem; table-layout: fixed;
            background: var(--card); border: 1px solid var(--border);
            border-radius: 8px; overflow: hidden;
          }
          th, td {
            text-align: left; padding: 0.5rem 0.75rem;
            border-bottom: 1px solid var(--border); vertical-align: top;
          }
          tbody tr:last-child td { border-bottom: none; }
          td:first-child { font-family: var(--mono); font-size: 0.85rem; overflow-wrap: anywhere; }
          th {
            position: sticky; top: 0; background: #eef1f4; z-index: 1;
            font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em;
            color: var(--muted);
          }
          tbody tr:nth-child(even) { background: #fafbfc; }
          tbody tr:hover { background: #eef4ff; }
          tr.failed, tr.failed:nth-child(even) { background: var(--fail-bg); }
          tr.skipped, tr.skipped:nth-child(even) { background: var(--skip-bg); }
          td.time { font-family: var(--mono); font-size: 0.85rem; color: var(--muted); }

          .badge {
            display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px;
            font-size: 0.72rem; font-weight: 700; letter-spacing: 0.03em;
          }
          .status-pass { background: var(--pass-bg); color: var(--pass); }
          .status-fail { background: var(--fail-bg); color: var(--fail); }
          .status-skip { background: var(--skip-bg); color: var(--skip); }
          pre {
            margin: 0.4rem 0 0; padding: 0.5rem 0.6rem; white-space: pre-wrap;
            color: var(--fail); background: #fff; border: 1px solid var(--border);
            border-radius: 6px; font-size: 0.8rem;
          }
        </style>
      </head>
      <body>
        <h1><xsl:value-of select="$title"/></h1>
        <div class="summary">
          <div class="card">
            <span class="label">Total</span>
            <span class="value"><xsl:value-of select="@tests"/></span>
          </div>
          <div class="card c-fail">
            <xsl:if test="@failures = 0"><xsl:attribute name="class">card c-fail zero</xsl:attribute></xsl:if>
            <span class="label">Failures</span>
            <span class="value"><xsl:value-of select="@failures"/></span>
          </div>
          <div class="card c-fail">
            <xsl:if test="@errors = 0"><xsl:attribute name="class">card c-fail zero</xsl:attribute></xsl:if>
            <span class="label">Errors</span>
            <span class="value"><xsl:value-of select="@errors"/></span>
          </div>
          <div class="card c-skip">
            <xsl:if test="sum(testsuite/@skipped) = 0"><xsl:attribute name="class">card c-skip zero</xsl:attribute></xsl:if>
            <span class="label">Skipped</span>
            <span class="value"><xsl:value-of select="sum(testsuite/@skipped)"/></span>
          </div>
          <div class="card">
            <span class="label">Time</span>
            <span class="value"><xsl:value-of select="@time"/>s</span>
          </div>
        </div>
        <xsl:for-each select="testsuite">
          <h2><xsl:value-of select="@name"/>
            <xsl:text> </xsl:text>
            <span class="count">(<xsl:value-of select="count(testcase)"/> tests, <xsl:value-of select="@time"/>s)</span>
          </h2>
          <table>
            <colgroup>
              <col/>
              <col style="width: 6rem;"/>
              <col style="width: 6rem;"/>
            </colgroup>
            <thead>
              <tr><th>Test</th><th>Status</th><th>Time</th></tr>
            </thead>
            <tbody>
            <xsl:for-each select="testcase">
              <xsl:choose>
                <xsl:when test="failure or error">
                  <tr class="failed">
                    <td><xsl:value-of select="@name"/>
                      <pre><xsl:value-of select="failure | error"/></pre>
                    </td>
                    <td><span class="badge status-fail">FAIL</span></td>
                    <td class="time"><xsl:value-of select="@time"/>s</td>
                  </tr>
                </xsl:when>
                <xsl:when test="skipped">
                  <tr class="skipped">
                    <td><xsl:value-of select="@name"/></td>
                    <td><span class="badge status-skip">SKIP</span></td>
                    <td class="time"><xsl:value-of select="@time"/>s</td>
                  </tr>
                </xsl:when>
                <xsl:otherwise>
                  <tr>
                    <td><xsl:value-of select="@name"/></td>
                    <td><span class="badge status-pass">PASS</span></td>
                    <td class="time"><xsl:value-of select="@time"/>s</td>
                  </tr>
                </xsl:otherwise>
              </xsl:choose>
            </xsl:for-each>
            </tbody>
          </table>
        </xsl:for-each>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
