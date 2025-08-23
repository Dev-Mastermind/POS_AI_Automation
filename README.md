# AI-Assisted API Automation POC for Hanwha Vision

A comprehensive Proof of Concept demonstrating fast automation setup, practical AI integration, and release confidence metrics for API testing.

## 🚀 Quick Start

### Prerequisites
- Python 3.13+ (tested with Python 3.13.7)
- Git
- Windows PowerShell (for Windows users)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd POS_AI_Automation
   ```

2. **Create and activate virtual environment**
   ```bash
   # Create virtual environment
   python -m venv venv
   
   # Activate virtual environment
   # Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   
   # Windows Command Prompt:
   .\venv\Scripts\activate.bat
   
   # Linux/Mac:
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   # Install all dependencies
   pip install -r requirements.txt

4. **Verify installation**
   ```bash
   python -m pytest --version
   ```

## 🧪 Running Tests

### Basic Test Execution
```bash
# Run all tests
python -m pytest

# Run with verbose output
python -m pytest -v

# Run specific test file
python -m pytest tests/test_users.py -v

# Run tests by marker
python -m pytest -m integration -v
python -m pytest -m security -v
python -m pytest -m schemathesis -v
```

### Test Categories
- **Core API Tests**: Basic CRUD operations and schema validation
- **Security Tests**: SQL injection, XSS, authentication, rate limiting
- **Schemathesis Tests**: Property-based testing and fuzzing

### Generate Reports
```bash
# HTML report
python -m pytest --html=reports/report.html

# JSON report
python -m pytest --json-report --json-report-file=reports/report.json

# Coverage report
python -m pytest --cov=tests --cov-report=html:reports/coverage

# Allure report (if installed)
python -m pytest --alluredir=reports/allure
```

## 🏗️ Project Structure

```
POS_AI_Automation/
├── tests/                          # Test suites
│   ├── test_users.py              # Core API tests
│   ├── test_security.py           # Security tests
│   └── test_schemathesis.py       # Property-based tests
├── conftest.py                     # PyTest fixtures and configuration
├── pytest.ini                     # PyTest configuration
├── requirements.txt                # Full dependencies
├── requirements-minimal.txt        # Minimal dependencies for Python 3.13
├── openapi_spec.yaml              # OpenAPI specification
├── scripts/                        # Utility scripts
├── docs/                          # Documentation
├── reports/                        # Test reports (generated)
└── .github/workflows/             # CI/CD pipeline
```

## 🔧 Configuration

### Environment Variables
Copy `env.example` to `.env` and configure:
```bash
cp env.example .env
# Edit .env with your API configuration
```

### PyTest Configuration
- **Test Discovery**: `tests/` directory
- **Markers**: `integration`, `security`, `schemathesis`
- **Reports**: HTML, JSON, coverage
- **Parallel Execution**: Available with `pytest-xdist`

## 📊 Metrics & Reporting

### Available Reports
- **HTML Reports**: Professional test execution reports
- **Coverage Reports**: Code coverage analysis
- **JSON Reports**: Machine-readable test results
- **Allure Reports**: Rich, interactive test reports

### Metrics Dashboard
Run the metrics generation script:
```bash
# Use the simplified version (recommended for Windows)
python scripts/generate_metrics_simple.py

# Or use the full version (may have encoding issues on Windows)
python scripts/generate_metrics.py
```

This generates:
- HTML dashboard with test metrics
- JSON metrics file
- Prometheus-compatible metrics

## 🤖 AI Integration Examples

### Postman Postbot
- Generate test cases from API descriptions
- AI-suggested test scenarios
- Engineer validation and enhancement

### Cursor AI / GitHub Copilot
- Code scaffolding for test functions
- Test data generation
- Assertion suggestions

See `docs/ai_integration_examples.md` for detailed examples.

## 🚀 CI/CD Pipeline

### GitHub Actions
The project includes a complete CI/CD pipeline:
- **Multi-Python Testing**: Python 3.8, 3.9, 3.10
- **Test Execution**: Unit, integration, security, schemathesis
- **Report Generation**: HTML, JSON, coverage
- **Security Scanning**: Bandit, Safety
- **Artifact Publishing**: Test reports as GitHub artifacts

### Local CI Simulation
```bash
# Run the full test suite locally
python run_tests.py

# Or simulate CI pipeline
python -m pytest tests/ --html=reports/report.html --json-report --cov=tests
```

## 🛠️ Development

### Code Quality
```bash
# Format code
black .

# Lint code
flake8 .

# Security scan
bandit -r tests/
```

### Adding New Tests
1. Create test file in `tests/` directory
2. Use appropriate markers (`@pytest.mark.integration`, etc.)
3. Follow naming convention: `test_*.py`
4. Add to appropriate test category

### Custom Fixtures
Add shared fixtures in `conftest.py`:
```python
@pytest.fixture
def my_fixture():
    # Setup
    yield value
    # Teardown
```

## 📈 Performance & Monitoring

### Test Execution
- **Parallel Execution**: Use `pytest-xdist`
- **Test Selection**: Use markers for targeted testing
- **Performance Metrics**: Response time tracking in tests

### Monitoring Integration
- **Prometheus Metrics**: Available via metrics script
- **Grafana Dashboards**: Pre-configured dashboard JSON
- **Custom Metrics**: Extensible metrics framework

## 🆘 Troubleshooting

### Common Issues

**Virtual Environment Not Activating**
```bash
# Windows PowerShell execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then activate
.\venv\Scripts\Activate.ps1
```

**Package Installation Issues**
```bash
# Upgrade pip
python -m pip install --upgrade pip

# Clear cache
pip cache purge

# Use minimal requirements for Python 3.13
pip install -r requirements-minimal.txt
```

**Test Failures**
```bash
# Run with verbose output
python -m pytest -v --tb=long

# Check specific test
python -m pytest tests/test_users.py::TestUsersAPI::test_get_users_returns_200_and_schema_match -v
```

### Getting Help
- Check test output for detailed error messages
- Verify virtual environment is activated
- Ensure all dependencies are installed
- Review `pytest.ini` configuration

## 🎯 Next Steps

### Immediate Actions
1. ✅ **Setup Complete**: Virtual environment and dependencies
2. ✅ **Tests Running**: All 21 tests passing
3. ✅ **Reports Working**: HTML, JSON, coverage reports

### Future Enhancements
- Integrate with real Hanwha Vision APIs
- Add more comprehensive test coverage
- Implement anomaly detection
- Expand AI integration examples
- Add performance benchmarking

## 📞 Support

For questions or issues:
- Review this README
- Check test output and error messages
- Ensure virtual environment is properly activated
- Verify Python version compatibility (3.13+)

---

**Status**: ✅ **POC Complete - Ready for Monday Delivery**
**Test Results**: 21/21 tests passing (100%)
**Framework**: PyTest + Schemathesis + AI Integration
**Environment**: Python 3.13.7 + Virtual Environment
