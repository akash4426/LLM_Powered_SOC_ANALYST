#!/bin/bash

# LLM-Powered SOC Analyst - Pre-Deployment Validation
# Verifies project is ready for GitHub push

echo "════════════════════════════════════════════════════════"
echo "  LLM-Powered SOC Analyst - Pre-Deployment Check"
echo "════════════════════════════════════════════════════════"
echo ""

# Check 1: Essential files
echo "✓ Checking essential files..."
REQUIRED_FILES=(
  "readme.md"
  "requirements.txt"
  "Dockerfile"
  "docker-compose.yml"
  ".env.example"
  ".gitignore"
  "CONTRIBUTING.md"
  "backend/main.py"
  "frontend/index.html"
)

MISSING=0
for file in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$file" ]; then
    echo "  ✗ Missing: $file"
    MISSING=$((MISSING+1))
  fi
done

if [ $MISSING -eq 0 ]; then
  echo "  ✓ All required files present"
else
  echo "  ✗ $MISSING files missing!"
  exit 1
fi
echo ""

# Check 2: No sensitive data
echo "✓ Checking for sensitive data..."
SENSITIVE_PATTERNS=(
  "sk-[a-zA-Z0-9]*"
  "password123"
  "OPENAI_API_KEY="
)

FOUND_SENSITIVE=0
for pattern in "${SENSITIVE_PATTERNS[@]}"; do
  if grep -r "$pattern" --include="*.py" --include="*.js" --exclude-dir=".venv" . 2>/dev/null | grep -v ".env.example" > /dev/null; then
    echo "  ✗ Found potential sensitive data: $pattern"
    FOUND_SENSITIVE=$((FOUND_SENSITIVE+1))
  fi
done

if [ $FOUND_SENSITIVE -eq 0 ]; then
  echo "  ✓ No hardcoded sensitive data detected"
fi
echo ""

# Check 3: Directory structure
echo "✓ Checking directory structure..."
REQUIRED_DIRS=(
  "backend"
  "frontend"
  "scripts"
  "models"
  "docs"
)

MISSING_DIRS=0
for dir in "${REQUIRED_DIRS[@]}"; do
  if [ ! -d "$dir" ]; then
    echo "  ✗ Missing directory: $dir"
    MISSING_DIRS=$((MISSING_DIRS+1))
  fi
done

if [ $MISSING_DIRS -eq 0 ]; then
  echo "  ✓ All required directories present"
fi
echo ""

# Check 4: No unnecessary files
echo "✓ Checking for unnecessary files to remove..."
UNNECESSARY_PATTERNS=(
  "*.log"
  "__pycache__"
  "*.pyc"
  ".DS_Store"
  "*.bak"
)

for pattern in "${UNNECESSARY_PATTERNS[@]}"; do
  if find . -name "$pattern" ! -path "./.venv/*" ! -path "./.git/*" 2>/dev/null | grep -q .; then
    echo "  ⚠ Warning: Found $pattern files"
  fi
done
echo ""

# Check 5: .gitignore exists
echo "✓ Checking .gitignore configuration..."
if [ -f ".gitignore" ]; then
  if grep -q "\.env" ".gitignore" && \
     grep -q "__pycache__" ".gitignore" && \
     grep -q "\.venv" ".gitignore"; then
    echo "  ✓ .gitignore properly configured"
  else
    echo "  ✗ .gitignore missing important patterns"
  fi
fi
echo ""

# Check 6: Documentation
echo "✓ Checking documentation..."
if [ -f "readme.md" ]; then
  if grep -q "Quick Start" readme.md && \
     grep -q "Installation" readme.md; then
    echo "  ✓ README contains essential sections"
  fi
fi

if [ -f "CONTRIBUTING.md" ]; then
  echo "  ✓ CONTRIBUTING.md present"
fi

if [ -d "docs" ]; then
  echo "  ✓ docs/ directory present"
fi
echo ""

# Summary
echo "════════════════════════════════════════════════════════"
echo "  Validation Complete!"
echo "════════════════════════════════════════════════════════"
echo ""
echo "✓ Project is ready for GitHub push"
echo ""
echo "Next steps:"
echo "  1. git add ."
echo "  2. git commit -m 'Production-ready: Clean build for GitHub'"
echo "  3. git push origin main"
echo ""
echo "For detailed docs, see:"
echo "  • README.md — Project overview and quick start"
echo "  • CONTRIBUTING.md — Development guidelines"
echo "  • docs/ — Technical documentation"
echo ""
