#!/usr/bin/env python3

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

@dataclass
class GPOSetting:
    setting_type: str
    name: str
    enabled: bool
    value: Any
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TaniumPolicy:
    name: str
    id: str
    domain: str
    settings: Dict[str, List[GPOSetting]]

@dataclass
class ParsingStats:
    total_settings: int = 0
    failed_settings: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

class GPOConverter:
    def __init__(self, 
                 input_path: str, 
                 output_path: str, 
                 log_level: str = "INFO", 
                 pretty: bool = False,
                 fail_on_warnings: bool = False,
                 skip_audit: bool = False):
        self.input_path = Path(input_path)
        self.output_path = Path(output_path)
        self.pretty = pretty
        self.fail_on_warnings = fail_on_warnings
        self.skip_audit = skip_audit
        
        self.setup_logging(log_level)
        self.stats = ParsingStats()
        
        # XML namespaces should include more common GPO namespaces
        self.namespaces = {
            'gp': 'http://www.microsoft.com/GroupPolicy/Settings',
            'gpt': 'http://www.microsoft.com/GroupPolicy/Types',
            'q1': 'http://www.microsoft.com/GroupPolicy/Settings/Security',
            'q2': 'http://www.microsoft.com/GroupPolicy/Settings/Registry',
            'q3': 'http://www.microsoft.com/GroupPolicy/Settings/Audit'
        }

    def setup_logging(self, log_level: str):
        """Configure logging with appropriate format and level"""
        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f'Invalid log level: {log_level}')
        
        logging.basicConfig(
            level=numeric_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def load_gpo_files(self) -> List[ET.ElementTree]:
        """Load and validate GPO XML files"""
        gpo_files = []
        
        if self.input_path.is_file():
            self.logger.info(f"Processing single file: {self.input_path}")
            gpo_files.append(self.input_path)
        elif self.input_path.is_dir():
            self.logger.info(f"Processing directory: {self.input_path}")
            gpo_files.extend(self.input_path.glob("**/*.xml"))
        else:
            raise FileNotFoundError(f"Input path not found: {self.input_path}")

        if not gpo_files:
            raise ValueError("No GPO XML files found")

        return [ET.parse(str(f)) for f in gpo_files]

    def parse_security_options(self, xml_root: ET.ElementTree) -> List[GPOSetting]:
        """Parse security options from GPO XML"""
        settings = []
        security_options = xml_root.findall(".//gp:SecurityOptions/gp:SecurityOption", self.namespaces)
        
        for option in security_options:
            try:
                name = option.find("gp:Name", self.namespaces).text
                state = option.find("gp:State", self.namespaces).text
                setting = option.find("gp:Setting", self.namespaces).text

                settings.append(GPOSetting(
                    setting_type="security_option",
                    name=name,
                    enabled=(state and state.lower() == "enabled"),
                    value=setting
                ))
                self.stats.total_settings += 1
            except (AttributeError, TypeError) as e:
                self.logger.warning(f"Failed to parse security option: {e}")
                self.stats.failed_settings += 1
                self.stats.warnings.append(f"Failed to parse security option: {option.tag if option is not None else 'unknown'}")

        return settings

    def parse_registry_settings(self, xml_root: ET.ElementTree) -> List[GPOSetting]:
        """Parse registry settings from GPO XML"""
        settings = []
        registry_values = xml_root.findall(".//gp:RegistrySettings/gp:RegistrySetting", self.namespaces)
        
        for value in registry_values:
            try:
                key_path = value.find("gp:KeyPath", self.namespaces).text
                value_name = value.find("gp:ValueName", self.namespaces).text
                value_type = value.find("gp:ValueType", self.namespaces).text
                value_data = value.find("gp:Value", self.namespaces).text

                settings.append(GPOSetting(
                    setting_type="registry_value",
                    name=f"{key_path}\\{value_name}",
                    enabled=True,  # Registry settings are considered "enabled" if present
                    value=self._parse_registry_value(value_type, value_data),
                    metadata={"value_type": value_type}
                ))
                self.stats.total_settings += 1
            except (AttributeError, TypeError) as e:
                self.logger.warning(f"Failed to parse registry value: {e}")
                self.stats.failed_settings += 1

        return settings

    def _parse_registry_value(self, value_type: str, value_data: Optional[str]) -> Any:
        if not value_data:
            return None

        try:
            if value_type == "REG_DWORD":
                return int(value_data, 16) if value_data.lower().startswith('0x') else int(value_data)
            elif value_type == "REG_MULTI_SZ":
                parts = value_data.split('\0')
                return [p for p in parts if p]  # More efficient list comprehension
            elif value_type == "REG_BINARY":
                # Add error handling for invalid hex strings
                try:
                    return bytes.fromhex(value_data).hex()
                except ValueError:
                    self.logger.warning(f"Invalid binary data: {value_data}")
                    return None
            return value_data
        except (ValueError, TypeError) as e:
            self.logger.warning(f"Error parsing registry value of type {value_type}: {e}")
            return None

    def parse_audit_settings(self, xml_root: ET.ElementTree) -> List[GPOSetting]:
        """Parse audit policy settings"""
        settings = []
        audit_policies = xml_root.findall(".//gp:AuditSettings/gp:AuditSetting", self.namespaces)
        
        for policy in audit_policies:
            try:
                name = policy.find("gp:SubcategoryName", self.namespaces).text
                success = policy.find("gp:SuccessfulAudit", self.namespaces).text
                failure = policy.find("gp:FailureAudit", self.namespaces).text
                
                settings.append(GPOSetting(
                    setting_type="audit_policy",
                    name=name,
                    enabled=True,
                    value={"success": success == "1", "failure": failure == "1"}
                ))
                self.stats.total_settings += 1
            except (AttributeError, TypeError) as e:
                self.logger.warning(f"Failed to parse audit policy: {e}")
                self.stats.failed_settings += 1

        return settings

    def extract_gpo_metadata(self, xml_root: ET.ElementTree) -> Dict[str, str]:
        """Extract GPO identifier and metadata"""
        try:
            identifier_elem = xml_root.find(".//gpt:Identifier", self.namespaces)
            domain_elem = xml_root.find(".//gpt:Domain", self.namespaces)
            name_elem = xml_root.find("gp:Name", self.namespaces)

            identifier = identifier_elem.text if identifier_elem is not None else None
            domain = domain_elem.text if domain_elem is not None else None
            name = name_elem.text if name_elem is not None else None

            if not all([identifier, domain, name]):
                self.logger.error("Missing critical GPO metadata.")
                self.stats.errors.append("Failed to extract GPO metadata")
                raise ValueError("Required GPO metadata missing")

            return {
                "id": identifier,
                "domain": domain,
                "name": name
            }
        except (AttributeError, TypeError) as e:
            self.logger.error(f"Failed to extract GPO metadata: {e}")
            self.stats.errors.append("Failed to extract GPO metadata")
            raise ValueError("Required GPO metadata missing")

    def convert_to_tanium_format(self, gpo_data: List[GPOSetting], metadata: Dict[str, str]) -> TaniumPolicy:
        """Convert GPO data to Tanium policy format"""
        settings_by_type = {}
        for setting in gpo_data:
            if setting.setting_type not in settings_by_type:
                settings_by_type[setting.setting_type] = []
            settings_by_type[setting.setting_type].append(setting)

        return TaniumPolicy(
            name=metadata["name"],
            id=metadata["id"],
            domain=metadata["domain"],
            settings=settings_by_type
        )

    def validate_tanium_policy(self, policy: TaniumPolicy) -> bool:
        """Validate the converted policy"""
        if not policy.name or not policy.id or not policy.domain:
            self.logger.error("Missing required policy metadata")
            return False
        
        if not policy.settings:
            self.logger.warning("Policy contains no settings")
            return False
            
        return True

    def save_output(self, policies: List[TaniumPolicy]):
        """Save the converted policies to JSON"""
        output_dir = self.output_path.parent
        output_dir.mkdir(parents=True, exist_ok=True)

        # Convert policies to dictionary format
        policy_dicts = []
        for policy in policies:
            policy_dict = {
                "name": policy.name,
                "id": policy.id,
                "domain": policy.domain,
                "settings": {
                    setting_type: [
                        {
                            "name": s.name,
                            "enabled": s.enabled,
                            "value": s.value,
                            **s.metadata
                        } for s in settings
                    ]
                    for setting_type, settings in policy.settings.items()
                }
            }
            policy_dicts.append(policy_dict)

        # Respect the --pretty flag for output indentation
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(policy_dicts, f, indent=2 if self.pretty else None)
        
        self.logger.info(f"Saved {len(policies)} policies to {self.output_path}")

    def process(self):
        """Main processing method"""
        try:
            gpo_files = self.load_gpo_files()
            policies = []

            for gpo_tree in gpo_files:
                try:
                    metadata = self.extract_gpo_metadata(gpo_tree)
                    settings = []
                    
                    # Parse different sections
                    settings.extend(self.parse_security_options(gpo_tree))
                    settings.extend(self.parse_registry_settings(gpo_tree))
                    
                    if not self.skip_audit:
                        settings.extend(self.parse_audit_settings(gpo_tree))
                    
                    policy = self.convert_to_tanium_format(settings, metadata)
                    
                    if self.validate_tanium_policy(policy):
                        policies.append(policy)
                    else:
                        self.logger.error(f"Policy validation failed for {metadata.get('name', 'unknown')}")
                
                except Exception as e:
                    self.logger.error(f"Failed to process GPO: {e}")
                    self.stats.errors.append(f"Failed to process GPO: {str(e)}")
                    continue

            if policies:
                self.save_output(policies)
            
            # Log summary
            self.logger.info("\nProcessing Summary:")
            self.logger.info(f"Total settings processed: {self.stats.total_settings}")
            self.logger.info(f"Failed settings: {self.stats.failed_settings}")
            self.logger.info(f"Warnings: {len(self.stats.warnings)}")
            self.logger.info(f"Errors: {len(self.stats.errors)}")

            # Add clear warning message if there were any issues
            if self.stats.errors or self.stats.warnings or self.stats.failed_settings:
                self.logger.warning("⚠️  Conversion completed with issues. Review the logs above for details.")

            # If --fail-on-warnings was given, exit non-zero if warnings exist
            if self.fail_on_warnings and self.stats.warnings:
                self.logger.warning("Exiting with non-zero status due to warnings.")
                return False

            # Return False if any errors, True otherwise
            return len(self.stats.errors) == 0
            
        except Exception as e:
            self.logger.error(f"Processing failed: {e}")
            return False

def setup_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert Group Policy Objects (GPOs) to Tanium JSON format",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "input",
        help="Path to GPO XML file or directory containing GPO files",
        nargs='?'  # Make input optional for GUI mode
    )
    
    parser.add_argument(
        "output",
        help="Path for output JSON file",
        nargs='?'  # Make output optional for GUI mode
    )
    
    parser.add_argument(
        "-g", "--gui",
        action="store_true",
        help="Launch the graphical user interface"
    )
    
    parser.add_argument(
        "-l", "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level (default: INFO)"
    )
    
    parser.add_argument(
        "-p", "--pretty",
        action="store_true",
        help="Format output JSON for readability"
    )

    parser.add_argument(
        "-f", "--fail-on-warnings",
        action="store_true",
        help="Exit with a non-zero status if warnings were encountered"
    )

    parser.add_argument(
        "-a", "--skip-audit",
        action="store_true",
        help="Skip parsing of audit policy settings"
    )
    
    return parser

class GPOConverterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("GPO Converter")
        self.root.geometry("600x400")
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Input file/directory selection
        ttk.Label(main_frame, text="Input Path:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_path = tk.StringVar()
        input_entry = ttk.Entry(main_frame, textvariable=self.input_path, width=50)
        input_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_input).grid(row=0, column=2, padx=5, pady=5)
        
        # Output file selection
        ttk.Label(main_frame, text="Output Path:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.output_path = tk.StringVar()
        output_entry = ttk.Entry(main_frame, textvariable=self.output_path, width=50)
        output_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=1, column=2, padx=5, pady=5)
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="5")
        options_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Log level selection
        ttk.Label(options_frame, text="Log Level:").grid(row=0, column=0, sticky=tk.W)
        self.log_level = tk.StringVar(value="INFO")
        log_combo = ttk.Combobox(options_frame, textvariable=self.log_level, 
                                values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                                state="readonly", width=10)
        log_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Checkboxes
        self.pretty = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Pretty Print JSON", 
                       variable=self.pretty).grid(row=0, column=2, padx=20)
        
        self.fail_on_warnings = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Fail on Warnings",
                       variable=self.fail_on_warnings).grid(row=0, column=3, padx=20)
        
        self.skip_audit = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Skip Audit Settings",
                       variable=self.skip_audit).grid(row=0, column=4, padx=20)
        
        # Log output
        log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding="5")
        log_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        self.log_text = tk.Text(log_frame, height=10, width=70)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.log_text['yscrollcommand'] = scrollbar.set
        
        # Convert button
        ttk.Button(main_frame, text="Convert", command=self.convert).grid(row=4, column=0, columnspan=3, pady=10)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Set up logging
        self.setup_logging()
        
        # Add cleanup method
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_logging(self):
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget
            
            def emit(self, record):
                msg = self.format(record) + '\n'
                self.text_widget.insert(tk.END, msg)
                self.text_widget.see(tk.END)
        
        # Clear existing handlers
        logging.getLogger().handlers = []
        
        # Configure logging to text widget
        handler = TextHandler(self.log_text)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)

    def browse_input(self):
        """
        Prompt the user explicitly whether they want to
        select a directory or an XML file, then update self.input_path
        accordingly.
        """
        # Ask user if they want to pick a directory or a file
        choice = messagebox.askyesno(
            "Select GPO Source",
            "Do you want to select a directory?\n\n"
            "Click 'Yes' to select a directory.\n"
            "Click 'No' to select a single GPO XML file."
        )
        if choice:
            # User wants to pick a directory
            path = filedialog.askdirectory()
        else:
            # User wants to pick a single XML file
            path = filedialog.askopenfilename(
                filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
            )

        if path:
            self.input_path.set(path)

    def browse_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if path:
            self.output_path.set(path)

    def convert(self):
        if not self.input_path.get() or not self.output_path.get():
            messagebox.showerror("Error", "Please specify both input and output paths.")
            return
        
        self.log_text.delete(1.0, tk.END)  # Clear previous log output
        
        try:
            converter = GPOConverter(
                input_path=self.input_path.get(),
                output_path=self.output_path.get(),
                log_level=self.log_level.get(),
                pretty=self.pretty.get(),
                fail_on_warnings=self.fail_on_warnings.get(),
                skip_audit=self.skip_audit.get()
            )
            
            success = converter.process()
            
            if success:
                messagebox.showinfo("Success", "Conversion completed successfully!")
            else:
                messagebox.showwarning("Warning", "Conversion completed with warnings or errors. Check the log output.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Conversion failed: {str(e)}")
            logging.error(f"Conversion failed: {e}")

    def on_closing(self):
        """Clean up resources before closing"""
        logging.getLogger().handlers = []  # Clear logging handlers
        self.root.destroy()

def main():
    try:
        parser = setup_cli_parser()
        args = parser.parse_args()

        if args.gui or (not args.input and not args.output):
            import tkinter as tk
            root = tk.Tk()
            try:
                app = GPOConverterGUI(root)
                root.mainloop()
            except Exception as e:
                logging.error(f"GUI error: {e}")
                sys.exit(1)
        else:
            if not args.input or not args.output:
                parser.error("Both input and output paths are required in CLI mode")
                
            converter = GPOConverter(
                input_path=args.input,
                output_path=args.output,
                log_level=args.log_level,
                pretty=args.pretty,
                fail_on_warnings=args.fail_on_warnings,
                skip_audit=args.skip_audit
            )
            success = converter.process()
            sys.exit(0 if success else 1)
            
    except KeyboardInterrupt:
        logging.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unhandled error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()