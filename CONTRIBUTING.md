# Contributing to LLM-Powered SOC Analyst

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

Please be respectful and constructive in all interactions. We aim to create a welcoming community for all contributors.

## Getting Started

### Prerequisites
- Python 3.10+
- Git
- Basic understanding of security concepts

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/akash4426/LLM_Powered_SOC_ANALYST.git
cd LLM_Powered_SOC_ANALYST

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# or: .venv\Scripts\activate  # Windows

# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov black flake8

# Set up pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

## Development Workflow

### 1. Create a Branch

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

### 2. Make Changes

- Follow PEP 8 style guidelines
- Write descriptive commit messages
- Add tests for new functionality
- Update documentation as needed

### 3. Code Style

```bash
# Format code with Black
black backend/ frontend/

# Check style with Flake8
flake8 backend/ --max-line-length=100
```

### 4. Testing

```bash
# Run tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=backend tests/
```

### 5. Commit & Push

```bash
# Commit with descriptive message
git commit -m "feat: add new anomaly detection model"

# Push to your fork
git push origin feature/your-feature-name
```

## Pull Request Process

### Before Submitting

1. **Test your changes** — Run the full test suite
2. **Update documentation** — Add docstrings and update README if needed
3. **Check code style** — Run Black and Flake8
4. **Verify no conflicts** — Pull latest main branch

### PR Checklist

- [ ] Code follows PEP 8 style guidelines
- [ ] New features have corresponding tests
- [ ] Tests pass locally (`pytest`)
- [ ] Documentation is updated
- [ ] Commit messages are descriptive
- [ ] No sensitive data (API keys, credentials) in code

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Unit tests added
- [ ] Integration tests passed
- [ ] Manual testing completed

## Related Issues
Closes #123

## Screenshots (if applicable)
Add screenshots for UI changes
```

## Areas for Contribution

### Backend
- [ ] New event types in `event_extractor.py`
- [ ] Additional threat intelligence sources
- [ ] LSTM model improvements
- [ ] Performance optimizations

### Frontend
- [ ] UI/UX improvements
- [ ] Visualization enhancements
- [ ] Scenario additions
- [ ] Accessibility improvements

### Documentation
- [ ] API documentation
- [ ] Deployment guides
- [ ] Tutorial content
- [ ] Architecture diagrams

### DevOps
- [ ] Docker improvements
- [ ] Kubernetes manifests
- [ ] CI/CD pipeline
- [ ] Monitoring setup

## Reporting Issues

### Bug Reports

Provide:
1. **Description** — Clear explanation of the issue
2. **Steps to reproduce** — Exact steps to reproduce
3. **Expected vs actual behavior**
4. **Environment** — Python version, OS, dependencies
5. **Logs/Screenshots** — Relevant error messages

### Feature Requests

Include:
1. **Use case** — Why this feature is needed
2. **Proposed solution** — How it should work
3. **Alternatives** — Other possible approaches
4. **Examples** — Code examples if applicable

## Project Structure

```
backend/           # Core analysis engine
  ├── ingestion/  # Log parsing
  ├── processing/ # Event extraction & correlation
  ├── reasoning/  # LLM & agent layer
  ├── models/     # LSTM anomaly detection
  ├── rag/        # MITRE ATT&CK retrieval
  └── api/        # API endpoints

frontend/          # Web UI
  ├── index.html
  ├── app.js
  └── style.css

tests/             # Test suite
  ├── test_backend/
  └── test_frontend/

scripts/           # Utility scripts
  ├── train_lstm.py
  ├── evaluate_lstm.py
  └── download_models.py
```

## Key Technologies

- **FastAPI** — REST API framework
- **PyTorch** — LSTM anomaly detection
- **ChromaDB** — Vector database for RAG
- **OpenAI** — LLM integration
- **NetworkX** — Graph analysis

## Development Tips

### Running the System Locally

```bash
# Terminal 1: Start API server
python -m uvicorn backend.main:app --reload

# Terminal 2: Serve frontend
# Open frontend/index.html in browser
# or use live server extension in VS Code
```

### Debugging

```bash
# Run with debug logging
DEBUG=true python -m uvicorn backend.main:app --reload

# Python debugger
import pdb; pdb.set_trace()

# Print debugging
import json; print(json.dumps(data, indent=2))
```

### Common Tasks

```bash
# Download LSTM model
python scripts/download_models.py

# Build MITRE RAG database
python backend/rag/build_mitre_db.py

# Generate synthetic test data
python scripts/generate_dataset.py

# Evaluate LSTM model
python scripts/evaluate_lstm.py
```

## Commit Message Guidelines

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- **feat** — New feature
- **fix** — Bug fix
- **docs** — Documentation
- **style** — Code style
- **refactor** — Code refactoring
- **perf** — Performance improvement
- **test** — Test changes
- **chore** — Build/dependency changes

### Examples
```
feat(agent-layer): implement cross-session correlation
fix(lstm-model): resolve tensor dimension mismatch
docs(api): add endpoint examples
refactor(event-extractor): improve event classification logic
```

## Questions?

- Open an issue with the `question` label
- Check existing issues and discussions
- Email: akash4426@gmail.com

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- GitHub contributors page

Thank you for contributing to the project! 🙏
