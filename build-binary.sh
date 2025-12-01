#!/bin/bash
# Build script for wg-friend binary
# Ensures clean build with all dependencies

set -e  # Exit on error

echo "======================================================================"
echo "Building wg-friend binary with PyInstaller"
echo "======================================================================"

# Check Python version
python_version=$(python3 --version)
echo "Python version: $python_version"

# Check PyInstaller version
pyinstaller_version=$(pyinstaller --version)
echo "PyInstaller version: $pyinstaller_version"

# Check required dependencies
echo ""
echo "Checking dependencies..."
python3 -c "import nacl; print(f'  PyNaCl: OK ({nacl.__version__})')"
python3 -c "import cffi; print(f'  CFFI: OK ({cffi.__version__})')"
python3 -c "import _cffi_backend; print(f'  _cffi_backend: OK ({_cffi_backend.__file__})')"

# Clean previous builds
echo ""
echo "Cleaning previous builds..."
rm -rf build/wg-friend dist/wg-friend

# Build with --clean flag
echo ""
echo "Running PyInstaller..."
pyinstaller --clean v1/wg-friend.spec

# Verify binary was created
if [ ! -f dist/wg-friend ]; then
    echo "ERROR: Binary not created!"
    exit 1
fi

# Get binary size
binary_size=$(du -h dist/wg-friend | cut -f1)
echo ""
echo "======================================================================"
echo "Build complete!"
echo "======================================================================"
echo "Binary location: dist/wg-friend"
echo "Binary size: $binary_size"

# Test binary
echo ""
echo "Testing binary..."
dist/wg-friend --version

echo ""
echo "======================================================================"
echo "Build successful! Next steps:"
echo "  1. Test: ./dist/wg-friend --help"
echo "  2. Commit: git add dist/wg-friend"
echo "  3. Push: git commit -m 'Rebuild binary for vX.X.X'"
echo "======================================================================"
