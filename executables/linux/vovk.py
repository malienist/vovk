import subprocess
import sys
import random
import os

def read_elf_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            return file.read()
    except Exception as e:
        print(f"Error reading ELF file: {e}")
        return None

def run_strings(file_path):
    try:
        result = subprocess.run(['strings', file_path], capture_output=True, text=True, check=True)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        print(f"Error running strings on {file_path}: {e}")
        return []

def string_to_hex(string):
    return ' '.join(f'{ord(c):02x}' for c in string)

def generate_yara_rule(strings_list, rule_name="vovk_elf"):
    if len(strings_list) > 20:
        strings_list = random.sample(strings_list, 20)

    yara_rule = f'rule {rule_name} {{\n'
    yara_rule += '    strings:\n'
    for idx, string in enumerate(strings_list):
        hex_string = string_to_hex(string)
        yara_rule += f'        $str{idx} = {{ {hex_string} }}\n\n'
    yara_rule += '    condition:\n'
    yara_rule += '        all of them\n'
    yara_rule += '}\n'
    return yara_rule

def create_yara_rule_from_elf(file_path, rule_name="vovk_elf"):
    print(f"Reading ELF file: {file_path}")
    elf_data = read_elf_file(file_path)
    if not elf_data:
        print(f"Failed to read ELF file: {file_path}")
        return ""
    
    print(f"Running strings on ELF file: {file_path}")
    strings_list = run_strings(file_path)
    if not strings_list:
        print(f"No strings found in ELF file: {file_path}")
        return ""
    
    print(f"Generating YARA rule from strings")
    yara_rule = generate_yara_rule(strings_list, rule_name)
    print(f"Generated YARA rule:\n{yara_rule}")  # Debug: Print the generated rule
    return yara_rule

def write_yara_rule_to_file(yara_rule, output_file="rule.yar"):
    try:
        # Ensure the file is overwritten by opening it in write mode
        with open(output_file, 'w') as file:
            file.write(yara_rule)
        print(f"YARA rule written to {output_file}")
    except Exception as e:
        print(f"Error writing YARA rule to file: {e}")

def interactive_session():
    yara_filename = input("Enter YARA Filename (*.yar): ")
    if not yara_filename.endswith('.yar'):
        print("Error: Filename must end with .yar")
        sys.exit(1)
    
    rule_name = input("Enter Rule Name (*_rule): ")
    if not rule_name.endswith('_rule'):
        print("Error: Rule name must end with _rule")
        sys.exit(1)

    return yara_filename, rule_name

if __name__ == "__main__":
    print("Choose an option:")
    print("1 for 'Quick Run'")
    print("2 for 'Interactive Session'")
    print("3 for 'Exit'")
    
    choice = input("Enter your choice: ")

    if choice == "1":
        yara_filename = "rule.yar"
        rule_name = "vovk_elf"
    elif choice == "2":
        yara_filename, rule_name = interactive_session()
    elif choice == "3":
        print("Exiting.")
        sys.exit(0)
    else:
        print("Invalid choice.")
        sys.exit(1)
    
    if len(sys.argv) != 2:
        print("Usage: python file.py path_to_elf_file")
        sys.exit(1)

    file_path = sys.argv[1]

    # Remove the existing rule file if it exists
    if os.path.exists(yara_filename):
        os.remove(yara_filename)
        print(f"Existing {yara_filename} file removed")  # Debug: Confirm file removal

    yara_rule = create_yara_rule_from_elf(file_path, rule_name)
    if yara_rule:
        write_yara_rule_to_file(yara_rule, yara_filename)
    else:
        print("Failed to generate YARA rule.")

