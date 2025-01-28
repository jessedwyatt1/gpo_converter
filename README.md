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

The converter can be used either through the command line interface (CLI) or graphical user interface (GUI).

### Command Line Interface

The basic syntax for the CLI is:

```bash
python gpo_converter.py INPUT OUTPUT [OPTIONS]
```

### Graphical User Interface

To launch the GUI, either:

```bash
python gpo_converter.py --gui
```

or simply:

```bash
python gpo_converter.py
```

The GUI provides an intuitive interface with:
- File/directory selection dialogs
- Option toggles for all settings
- Real-time log output
- Progress feedback

### Required Arguments

- `INPUT`: Path to GPO XML file or directory containing GPO files
- `OUTPUT`: Path for the output JSON file

### Optional Arguments

- `-g`, `--gui`: Launch the graphical user interface
- `-l`, `--log-level`: Set logging verbosity
  - Choices: DEBUG, INFO, WARNING, ERROR, CRITICAL
  - Default: INFO
- `-p`, `--pretty`: Format output JSON for readability
- `-f`, `--fail-on-warnings`: Exit with a non-zero status if warnings were encountered
- `-a`, `--skip-audit`: Skip parsing of audit policy settings

Note: When using GUI mode, the input and output path arguments become optional.

## Examples

### Convert a Single GPO File

```bash
python gpo_converter.py ./security-baseline.xml ./output.json
```

### Convert Multiple GPOs from a Directory

```bash
python gpo_converter.py ./gpo_exports/ ./all_policies.json
```

### CLI Examples

Enable Debug Logging:
```bash
python gpo_converter.py input.xml output.json -l DEBUG
```

Pretty Print Output:
```bash
python gpo_converter.py input.xml output.json -p
```

Skip Audit Policy Processing:
```bash
python gpo_converter.py input.xml output.json -a
```

Fail on Warnings:
```bash
python gpo_converter.py input.xml output.json -f
```

Launch GUI Mode:
```bash
python gpo_converter.py -g
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
  - All processing completed successfully
  - No errors encountered (warnings may exist if --fail-on-warnings not used)
- `1`: Error occurred during conversion
  - Processing failed
  - Critical errors encountered
  - Warnings encountered when --fail-on-warnings is enabled

## Best Practices

1. Always verify the output JSON matches your expected format
2. Use the `--log-level DEBUG` option when troubleshooting
3. Back up your original GPO files before conversion
4. Process GPOs in small batches when converting many files
5. Use `--fail-on-warnings` in automated pipelines to catch potential issues
6. Consider using `--skip-audit` if audit policies are not needed for your use case
7. When processing multiple files, use the GUI mode for better progress tracking and feedback
8. For automated processing, use CLI mode with appropriate flags

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
4. Verify that `--skip-audit` is not enabled if you need audit policies
