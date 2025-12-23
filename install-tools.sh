#!/bin/bash

# Security Tools Suite - Installation Script
# Uses curl (not wget), absolute paths, GitHub binaries only
# No .bashrc modifications - tools in /home/runner/${REPL_SLUG}/bin/

set -e

REPL_SLUG="${REPL_SLUG:-security-tools}"
BIN_DIR="/home/runner/${REPL_SLUG}/bin"
TEMP_DIR="/tmp/security-tools-install-$$"

echo "========================================"
echo "Security Tools Suite - Installation"
echo "========================================"
echo ""
echo "BIN_DIR: $BIN_DIR"
echo ""

# Create directories
mkdir -p "$BIN_DIR"
mkdir -p "$TEMP_DIR"

# ========================================
# 1. NUCLEI - Template-based scanner
# ========================================
echo "[*] Installing Nuclei..."
cd "$TEMP_DIR"
if curl -L -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v3.0.0/nuclei_3.0.0_linux_amd64.zip" 2>/dev/null; then
  unzip -q nuclei.zip || true
  if [ -f nuclei ]; then
    chmod +x nuclei
    mv nuclei "$BIN_DIR/nuclei"
    echo "✓ Nuclei installed"
  fi
  rm -f nuclei.zip
else
  echo "✗ Nuclei failed"
fi

# ========================================
# 2. SUBFINDER - Subdomain enumeration
# ========================================
echo "[*] Installing Subfinder..."
cd "$TEMP_DIR"
if curl -L -o subfinder.zip "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.0/subfinder_2.6.0_linux_amd64.zip" 2>/dev/null; then
  unzip -q subfinder.zip || true
  if [ -f subfinder ]; then
    chmod +x subfinder
    mv subfinder "$BIN_DIR/subfinder"
    echo "✓ Subfinder installed"
  fi
  rm -f subfinder.zip
else
  echo "✗ Subfinder failed"
fi

# ========================================
# 3. HTTPX - HTTP probing
# ========================================
echo "[*] Installing HTTPX..."
cd "$TEMP_DIR"
if curl -L -o httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v1.3.5/httpx_1.3.5_linux_amd64.zip" 2>/dev/null; then
  unzip -q httpx.zip || true
  if [ -f httpx ]; then
    chmod +x httpx
    mv httpx "$BIN_DIR/httpx"
    echo "✓ HTTPX installed"
  fi
  rm -f httpx.zip
else
  echo "✗ HTTPX failed"
fi

# ========================================
# 4. KATANA - Web crawler with JS
# ========================================
echo "[*] Installing Katana..."
cd "$TEMP_DIR"
if curl -L -o katana.zip "https://github.com/projectdiscovery/katana/releases/download/v1.0.0/katana_1.0.0_linux_amd64.zip" 2>/dev/null; then
  unzip -q katana.zip || true
  if [ -f katana ]; then
    chmod +x katana
    mv katana "$BIN_DIR/katana"
    echo "✓ Katana installed"
  fi
  rm -f katana.zip
else
  echo "✗ Katana failed"
fi

# ========================================
# 5. WAYBACKURLS - Historical URLs
# ========================================
echo "[*] Installing Waybackurls..."
cd "$TEMP_DIR"
if curl -L -o waybackurls "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64" 2>/dev/null; then
  chmod +x waybackurls
  mv waybackurls "$BIN_DIR/waybackurls"
  echo "✓ Waybackurls installed"
else
  echo "✗ Waybackurls failed"
fi

# ========================================
# 6. GAU - Get All URLs
# ========================================
echo "[*] Installing Gau..."
cd "$TEMP_DIR"
if curl -L -o gau.tar.gz "https://github.com/lc/gau/releases/download/v2.2.3/gau_2.2.3_linux_amd64.tar.gz" 2>/dev/null; then
  tar -xzf gau.tar.gz || true
  if [ -f gau ]; then
    chmod +x gau
    mv gau "$BIN_DIR/gau"
    echo "✓ Gau installed"
  fi
  rm -f gau.tar.gz
else
  echo "✗ Gau failed"
fi

# ========================================
# 7. SUBJS - JavaScript file extraction
# ========================================
echo "[*] Installing Subjs..."
cd "$TEMP_DIR"
if curl -L -o subjs.tar.gz "https://github.com/lc/subjs/releases/download/v0.0.2/subjs_0.0.2_linux_amd64.tar.gz" 2>/dev/null; then
  tar -xzf subjs.tar.gz || true
  if [ -f subjs ]; then
    chmod +x subjs
    mv subjs "$BIN_DIR/subjs"
    echo "✓ Subjs installed"
  fi
  rm -f subjs.tar.gz
else
  echo "✗ Subjs failed"
fi

# ========================================
# 8. SQLMAP - SQL injection testing
# ========================================
echo "[*] Installing SQLMap..."
cd "$TEMP_DIR"
if curl -L -o sqlmap.tar.gz "https://github.com/sqlmapproject/sqlmap/tarball/master" 2>/dev/null; then
  tar -xzf sqlmap.tar.gz || true
  # Find the extracted directory and move to bin
  sqlmap_dir=$(find . -maxdepth 1 -type d -name "sqlmapproject-sqlmap-*" 2>/dev/null | head -1)
  if [ -n "$sqlmap_dir" ] && [ -f "$sqlmap_dir/sqlmap.py" ]; then
    mv "$sqlmap_dir" "$BIN_DIR/sqlmap-git"
    # Create wrapper script
    cat > "$BIN_DIR/sqlmap" << 'SQLMAP_WRAPPER'
#!/bin/bash
python3 /home/runner/${REPL_SLUG}/bin/sqlmap-git/sqlmap.py "$@"
SQLMAP_WRAPPER
    chmod +x "$BIN_DIR/sqlmap"
    echo "✓ SQLMap installed (wrapper script)"
  fi
  rm -f sqlmap.tar.gz
else
  echo "✗ SQLMap failed"
fi

# ========================================
# VERIFICATION
# ========================================
echo ""
echo "========================================"
echo "Installation Verification"
echo "========================================"
echo ""

tools=("nuclei" "subfinder" "httpx" "katana" "waybackurls" "gau" "subjs" "sqlmap")
success_count=0

for tool in "${tools[@]}"; do
  if [ -f "$BIN_DIR/$tool" ] && [ -x "$BIN_DIR/$tool" ]; then
    echo "✓ $tool - Installed and verified"
    ((success_count++))
  else
    echo "✗ $tool - NOT FOUND"
  fi
done

echo ""
echo "========================================"
echo "Summary: $success_count/8 tools installed"
echo "========================================"
echo ""
echo "Tools location: $BIN_DIR"
echo ""
echo "To use these tools, set PATH:"
echo "  export PATH=\"$BIN_DIR:\$PATH\""
echo ""
echo "Or use absolute paths:"
echo "  $BIN_DIR/nuclei --version"
echo "  $BIN_DIR/katana --help"
echo ""

# Cleanup
rm -rf "$TEMP_DIR"

if [ $success_count -eq 8 ]; then
  echo "✓ All tools installed successfully!"
  exit 0
else
  echo "✗ Some tools failed to install (see above)"
  exit 1
fi
