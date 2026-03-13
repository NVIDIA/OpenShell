#!/bin/bash
# Check for unconverted MyST syntax in Fern docs

set -e

PAGES_DIR="${1:-fern/v0.1.0/pages}"

echo "=== Checking for unconverted MyST syntax in $PAGES_DIR ==="
echo ""

ISSUES_FOUND=0

echo "Checking for MyST directives (:::)..."
if grep -r ':::' "$PAGES_DIR" 2>/dev/null; then
    echo "⚠️  Found unconverted MyST directives (see above)"
    ISSUES_FOUND=1
else
    echo "✓ No MyST directives found"
fi
echo ""

echo "Checking for {ref} references (Sphinx cross-refs, not LaTeX \\text{ref})..."
if grep -rE '\{ref\}`' "$PAGES_DIR" 2>/dev/null || grep -rE '\{ref\} ' "$PAGES_DIR" 2>/dev/null; then
    echo "⚠️  Found unconverted {ref} references"
    ISSUES_FOUND=1
else
    echo "✓ No {ref} references found"
fi
echo ""

echo "Checking for {octicon} icons..."
if grep -r '{octicon}' "$PAGES_DIR" 2>/dev/null; then
    echo "⚠️  Found unconverted {octicon} icons"
    ISSUES_FOUND=1
else
    echo "✓ No {octicon} icons found"
fi
echo ""

echo "Checking for {py:class} / {py:meth} / {py:mod} / {py:attr} / {py:func} / {doc}..."
if grep -rE '\{py:(class|meth|mod|attr|func)\}' "$PAGES_DIR" 2>/dev/null || grep -rE '\{doc\}`' "$PAGES_DIR" 2>/dev/null; then
    echo "⚠️  Found unconverted py: or doc: roles"
    ISSUES_FOUND=1
else
    echo "✓ No py:/doc roles found"
fi
echo ""

echo "Checking for sphinx-design badges..."
if grep -r '{bdg-' "$PAGES_DIR" 2>/dev/null; then
    echo "⚠️  Found unconverted badges"
    ISSUES_FOUND=1
else
    echo "✓ No badges found"
fi
echo ""

echo "Checking for MyST mermaid syntax..."
if grep -r '```{mermaid}' "$PAGES_DIR" 2>/dev/null; then
    echo "⚠️  Found unconverted mermaid blocks (should be \`\`\`mermaid)"
    ISSUES_FOUND=1
else
    echo "✓ No MyST mermaid syntax found"
fi
echo ""

echo "=== Summary ==="
if [ $ISSUES_FOUND -eq 0 ]; then
    echo "✓ All checks passed"
    exit 0
else
    echo "⚠️  Some issues found - review and fix above"
    exit 1
fi
