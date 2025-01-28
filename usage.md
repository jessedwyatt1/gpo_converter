# GPO to Tanium Converter

A command-line utility for converting Windows Group Policy Objects (GPOs) to Tanium-compatible JSON format.

## Installation

1. Ensure Python 3.7+ is installed on your system
2. Download the `gpo_converter.py` script
3. Make the script executable (Linux/Mac):
   ```bash
   chmod +x gpo_converter.py
   ```

## Basic Usage

The basic syntax for the converter is:

```bash
python gpo_converter.py INPUT OUTPUT [OPTIONS]
```

### Required Arguments

- `INPUT`: Path to GPO XML file or directory containing GPO files
- `OUTPUT`: Path for the output JSON file

### Optional Arguments

- `--log-level`: Set logging verbosity
  - Choices: DEBUG, INFO, WARNING, ERROR, CRITICAL
  - Default: INFO
- `--pretty`: Format output JSON for readability

## Examples

### Convert a Single GPO File

```bash
python gpo_converter.py ./security-baseline.xml ./output.json
```

### Convert Multiple GPOs from a Directory

```bash
python gpo_converter.py ./gpo_exports/ ./all_policies.json
```

### Enable Debug Logging

```bash
python gpo_converter.py input.xml output.json --log-level DEBUG
```

### Pretty Print Output

```bash
python gpo_converter.py input.xml output.json --pretty
```

## Supported GPO Settings

The converter currently supports the following GPO setting types:

1. Security Options
   - Machine account lockout settings
   - Password policies
   - Security settings

2. Registry Settings
   - REG_SZ (String values)
   - REG_DWORD (32-bit numbers)
   - REG_BINARY (Binary data)
   - REG_MULTI_SZ (Multiple strings)

3. Audit Settings
   - Success/Failure auditing policies
   - System audit policies

## Output Format

The converter generates JSON output in the following format:

```json
[
  {
    "name": "Policy Name",
    "id": "Policy-GUID",
    "domain": "domain.com",
    "settings": {
      "security_option": [
        {
          "name": "Setting Name",
          "enabled": true,
          "value": "Setting Value"
        }
      ],
      "registry_value": [
        {
          "name": "HKLM\\Path\\ValueName",
          "enabled": true,
          "value": "Data",
          "value_type": "REG_SZ"
        }
      ]
    }
  }
]
```

## Error Handling

The converter provides detailed error reporting and continues processing even if individual settings fail. Error information includes:

- Total settings processed
- Failed settings count
- Warning messages
- Error details

Error output example:
```
Processing Summary:
Total settings processed: 150
Failed settings: 2
Warnings: 1
Errors: 0
```

## Exit Codes

- `0`: Successful conversion
- `1`: Error occurred during conversion

## Best Practices

1. Always verify the output JSON matches your expected format
2. Use the `--log-level DEBUG` option when troubleshooting
3. Back up your original GPO files before conversion
4. Process GPOs in small batches when converting many files

## Common Issues and Solutions

### XML Parsing Errors

If you encounter XML parsing errors:
1. Verify the input file is valid XML
2. Check for proper XML namespaces
3. Ensure the file uses UTF-8 encoding

### Missing Settings

If settings are missing from the output:
1. Check the input GPO XML contains the expected settings
2. Verify the settings are in a supported format
3. Enable DEBUG logging to see which settings were processed

