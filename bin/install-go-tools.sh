#!/bin/bash
# Install Go-based security tools for ShadowTwin PRO Pack
set -e

echo "🔧 Installing Go security tools..."

# Check if Go is available
if ! command -v go &> /dev/null; then
  echo "⚠️  Go not found. Using pre-compiled binaries instead..."
  exit 0
fi

TOOLS=(
  "github.com/hahwul/dalfox/v2@latest"
  "github.com/trufflesecurity/trufflehog/v3/cmd/trufflehog@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/tomnomnom/httpprobe@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/s0md3v/Arjun@latest"
  "github.com/assetnote/kiterunner/cmd/kr@latest"
)

for tool in "${TOOLS[@]}"; do
  echo "Installing $tool..."
  go install "$tool" && echo "✓ $(echo $tool | cut -d'/' -f3)"
done

# Copy binaries to workspace
cp ~/go/bin/* /home/runner/workspace/bin/ 2>/dev/null || true

echo "✅ All Go tools installed"
