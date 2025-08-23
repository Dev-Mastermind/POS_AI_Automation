# Manual Workflow Usage

This guide explains how to manually trigger the GitHub Actions workflow for testing and CI/CD operations.

## How to Manually Trigger the Workflow

### 1. Navigate to GitHub Actions
- Go to your repository on GitHub
- Click on the **Actions** tab

### 2. Select the Workflow
- Find **API Automation CI/CD Pipeline** in the workflows list
- Click on it to view the workflow details

### 3. Trigger Manual Execution
- Click the **Run workflow** button (blue button on the right)
- You'll see a form with configurable options

## Available Input Options

### Test Type
- **all**: Run all test types (default)
- **unit**: Run only unit tests
- **integration**: Run only integration tests  
- **security**: Run only security tests
- **schemathesis**: Run only API contract tests

### Python Version
- **3.8**: Python 3.8
- **3.9**: Python 3.9 (default)
- **3.10**: Python 3.10

### Job Execution Options
- **Run Integration**: Enable/disable integration tests (default: true)
- **Run Metrics**: Enable/disable metrics generation (default: true)
- **Run Security Scan**: Enable/disable security scanning (default: true)

## Example Use Cases

### Quick Smoke Test
- Test Type: `unit`
- Python Version: `3.9`
- Keep other options as default

### Full Security Validation
- Test Type: `security`
- Python Version: `3.10`
- Run Security Scan: `true`
- Other options can be disabled

### Complete Pipeline Test
- Test Type: `all`
- Python Version: `3.9`
- All job options enabled

## What Happens When You Trigger

1. **Test Job**: Runs the selected test types against the specified Python version
2. **Integration Job**: Runs if enabled and tests pass
3. **Metrics Job**: Generates dashboard if enabled
4. **Security Scan**: Performs security analysis if enabled
5. **Notification**: Sends completion status

## Viewing Results

- Check the workflow run logs for detailed execution
- Download test reports from the artifacts section
- Review any failure messages in the job logs

## Troubleshooting

- **Workflow not appearing**: Ensure you have the necessary permissions
- **Input validation errors**: Check that all required inputs are provided
- **Job failures**: Review the specific job logs for error details
