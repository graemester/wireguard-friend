#!/bin/bash
#
# WireGuard Friend - Distribution Package Creator
#
# Creates curated distribution packages for releases.
# See MANIFEST.md for what's included in each package.
#
# Usage:
#   ./create-distribution.sh [version]
#
# Example:
#   ./create-distribution.sh v1.0.0
#

set -e

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}WireGuard Friend - Distribution Package Creator${NC}"
echo ""

# Get version from argument or prompt
if [ -z "$1" ]; then
    echo -e "${YELLOW}Enter release version (e.g., v1.0.0, v1.2.3):${NC}"
    read -p "> " VERSION

    # Validate version format
    if [ -z "$VERSION" ]; then
        echo -e "${RED}Error: Version cannot be empty${NC}"
        exit 1
    fi

    # Add 'v' prefix if not present
    if [[ ! "$VERSION" =~ ^v ]]; then
        VERSION="v$VERSION"
        echo -e "${CYAN}Adding 'v' prefix: $VERSION${NC}"
    fi
else
    VERSION="$1"
fi

DIST_DIR="dist"

echo ""
echo -e "${GREEN}Creating distribution packages for version: $VERSION${NC}"
echo ""

# Clean and create dist directory
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# ============================================================================
# Package 1: Minimal (Core Only)
# ============================================================================

echo -e "${CYAN}Creating minimal package (core only)...${NC}"

MINIMAL_DIR="$DIST_DIR/wireguard-friend-minimal-$VERSION"
mkdir -p "$MINIMAL_DIR/src"

# Core scripts
cp wg-friend-onboard.py "$MINIMAL_DIR/"
cp wg-friend-maintain.py "$MINIMAL_DIR/"
cp requirements.txt "$MINIMAL_DIR/"

# Source code
cp src/*.py "$MINIMAL_DIR/src/"

# Minimal documentation
cp README.md "$MINIMAL_DIR/"
cp MANIFEST.md "$MINIMAL_DIR/"

# Create archive
cd "$DIST_DIR"
tar czf "wireguard-friend-minimal-$VERSION.tar.gz" "wireguard-friend-minimal-$VERSION/"
SIZE=$(du -h "wireguard-friend-minimal-$VERSION.tar.gz" | cut -f1)
echo -e "${GREEN}✓ Minimal package: wireguard-friend-minimal-$VERSION.tar.gz ($SIZE)${NC}"
cd ..

# ============================================================================
# Package 2: Standard (Core + Documentation)
# ============================================================================

echo -e "${CYAN}Creating standard package (core + docs)...${NC}"

STANDARD_DIR="$DIST_DIR/wireguard-friend-$VERSION"
mkdir -p "$STANDARD_DIR/src"

# Core scripts
cp wg-friend-onboard.py "$STANDARD_DIR/"
cp wg-friend-maintain.py "$STANDARD_DIR/"
cp backup-database.sh "$STANDARD_DIR/"
cp requirements.txt "$STANDARD_DIR/"

# Source code
cp src/*.py "$STANDARD_DIR/src/"

# User documentation
cp README.md "$STANDARD_DIR/"
cp DOCUMENTATION.md "$STANDARD_DIR/"
cp WHERE_TO_RUN.md "$STANDARD_DIR/"
cp QUICK_START.md "$STANDARD_DIR/"
cp BACKUP_RESTORE.md "$STANDARD_DIR/"
cp RESTRICTED_IP_ACCESS.md "$STANDARD_DIR/"
cp MANIFEST.md "$STANDARD_DIR/"

# License if it exists
[ -f LICENSE ] && cp LICENSE "$STANDARD_DIR/" || true

# Create archive
cd "$DIST_DIR"
tar czf "wireguard-friend-$VERSION.tar.gz" "wireguard-friend-$VERSION/"
SIZE=$(du -h "wireguard-friend-$VERSION.tar.gz" | cut -f1)
echo -e "${GREEN}✓ Standard package: wireguard-friend-$VERSION.tar.gz ($SIZE)${NC}"
cd ..

# ============================================================================
# Package 3: Complete (Everything)
# ============================================================================

echo -e "${CYAN}Creating complete package (everything)...${NC}"

COMPLETE_DIR="$DIST_DIR/wireguard-friend-complete-$VERSION"
mkdir -p "$COMPLETE_DIR/src"
mkdir -p "$COMPLETE_DIR/tests"

# Core scripts
cp wg-friend-onboard.py "$COMPLETE_DIR/"
cp wg-friend-maintain.py "$COMPLETE_DIR/"
cp backup-database.sh "$COMPLETE_DIR/"
cp requirements.txt "$COMPLETE_DIR/"

# Source code
cp src/*.py "$COMPLETE_DIR/src/"

# All documentation
cp README.md "$COMPLETE_DIR/"
cp DOCUMENTATION.md "$COMPLETE_DIR/"
cp WHERE_TO_RUN.md "$COMPLETE_DIR/"
cp QUICK_START.md "$COMPLETE_DIR/"
cp BACKUP_RESTORE.md "$COMPLETE_DIR/"
cp RESTRICTED_IP_ACCESS.md "$COMPLETE_DIR/"
cp ARCHITECTURE.md "$COMPLETE_DIR/"
cp MANIFEST.md "$COMPLETE_DIR/"

# Tests and utilities
cp tests/*.py "$COMPLETE_DIR/tests/"
cp tests/README.md "$COMPLETE_DIR/tests/"

# License if it exists
[ -f LICENSE ] && cp LICENSE "$COMPLETE_DIR/" || true

# Create archive
cd "$DIST_DIR"
tar czf "wireguard-friend-complete-$VERSION.tar.gz" "wireguard-friend-complete-$VERSION/"
SIZE=$(du -h "wireguard-friend-complete-$VERSION.tar.gz" | cut -f1)
echo -e "${GREEN}✓ Complete package: wireguard-friend-complete-$VERSION.tar.gz ($SIZE)${NC}"
cd ..

# ============================================================================
# Create checksums
# ============================================================================

echo ""
echo -e "${CYAN}Creating checksums...${NC}"

cd "$DIST_DIR"
sha256sum *.tar.gz > SHA256SUMS
echo -e "${GREEN}✓ Checksums created: SHA256SUMS${NC}"
cd ..

# ============================================================================
# Summary
# ============================================================================

echo ""
echo -e "${GREEN}======================================"
echo -e "Distribution packages created!"
echo -e "======================================${NC}"
echo ""
echo -e "${CYAN}Location:${NC} $DIST_DIR/"
echo ""
echo -e "${CYAN}Packages created:${NC}"
ls -lh "$DIST_DIR"/*.tar.gz | awk '{print "  " $9 " (" $5 ")"}'
echo ""
echo -e "${CYAN}Checksums:${NC} $DIST_DIR/SHA256SUMS"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Test the packages by extracting and running them"
echo "  2. Create a GitHub Release with version tag: $VERSION"
echo "  3. Upload the archives to the release"
echo "  4. Include SHA256SUMS in release notes"
echo ""
echo -e "${CYAN}Recommended for most users:${NC} wireguard-friend-$VERSION.tar.gz"
echo ""
