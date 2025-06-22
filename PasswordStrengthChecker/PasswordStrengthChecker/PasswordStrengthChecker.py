
from pickletools import read_stringnl_noescape_pair
import math
import string
from pathlib import Path
import os

# Constants
DEFAULT_POLICY = {
    'min_length': 8,
    'require_upper': True,
    'require_lower': True,
    'require_digit': True,
    'require_special': True
}

# Lengths
MIN_LENGTH = 8
MED_LENGTH = 12
LONG_LENGTH = 17
V_LONG_LENGTH = 20
LENGTH_THRESHOLDS = [MIN_LENGTH, MED_LENGTH, LONG_LENGTH, V_LONG_LENGTH]

# Thresholds
WEAK_THRESHOLD = 3
NORMAL_THRESHOLD = 6

score = 0

script_dir = Path(__file__).parent
file_path = script_dir / 'passwords.txt'

with file_path.open('r') as f:
    common = f.read().splitlines()

def get_password_from_user():
    return input("Enter your password: ")

def get_user_policy():
    print("Would you like to customise the password policy? (y/n, default n)")

    choice = input().strip().lower()
    if choice != 'y':
        return DEFAULT_POLICY.copy()

    min_length = input(f"Minimum password length? (default {DEFAULT_POLICY['min_length']}): ").strip()
    min_length = int(min_length) if min_length else DEFAULT_POLICY['min_length']

    require_upper = input("Require uppercase? (y/n, default y): ").strip().lower()
    require_upper = require_upper != 'n'

    require_lower = input("Require lowercase? (y/n, default y): ").strip().lower()
    require_lower = require_lower != 'n'

    require_digit = input("Require digit? (y/n, default y): ").strip().lower()
    require_digit = require_digit != 'n'

    require_special = input("Require special character? (y/n, default y): ").strip().lower()
    require_special = require_special != 'n'

    return {
        'min_length': min_length,
        'require_upper': require_upper,
        'require_lower': require_lower,
        'require_digit': require_digit,
        'require_special': require_special}

def check_char_type (password, policy):
    if policy['require_upper'] and not any(c.isupper() for c in password):
        return False, "Add at least one uppercase letter."
    if policy['require_lower'] and not any(c.islower() for c in password):
        return False, "Add at least one lowercase letter."
    if policy['require_digit'] and not any(c.isdigit() for c in password):
        return False, "Add at least one digit."
    if policy['require_special'] and not any(c in string.punctuation for c in password):
        return False, "Add at least one special character."
    return True, ""

    # Check character types
    upper_case = any(c in string.ascii_uppercase for c in password)
    lower_case = any(c in string.ascii_lowercase for c in password)
    special = any(c in string.punctuation for c in password)
    digits = any(c in string.digits for c in password)

    # Non-ASCII (accents, etc.)
    non_ascii = any(ord(c) > 127 for c in password)

    type_count = sum([upper_case, lower_case, special, digits])
    return type_count - 1

def check_common (password, common):
    # Check if common
    return password in common

def check_length(password, policy):
    if len(password) < policy['min_length']:
        return False, f"Password should be at least {policy['min_length']} characters long."
    return True, ""

def get_strength_category(score):
    if score <= WEAK_THRESHOLD:
        return "Weak"
    elif score <= NORMAL_THRESHOLD:
        return "Normal"
    else:
        return "Strong"

def calculate_entropy(password):
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)
    if any(ord(c) > 127 for c in password):
        charset_size += 100

    # Add more for extra characters as needed
    if charset_size == 0:
        return 0
    return len(password) * math.log2(charset_size)

def estimate_crack_time_seconds(entropy_bits, guesses_per_second=1e10):
    return 2 ** entropy_bits / guesses_per_second

def get_password_suggestions(password, common):
    suggestions = []

    # Length suggestions
    if len(password) < MIN_LENGTH:
        suggestions.append(f"Make your password at least {MIN_LENGTH} characters long.")
    elif len(password) < MED_LENGTH:
        suggestions.append(f"Longer passwords are stronger. Try to use at least {MIN_LENGTH} characters.")

    # Character type suggestions
    if not any(c in string.ascii_lowercase for c in password):
        suggestions.append("Add at least one lowercase letter.")
    if not any(c in string.ascii_uppercase for c in password):
        suggestions.append("Add at least one uppercase letter.")
    if not any(c in string.digits for c in password):
        suggestions.append("Add at least one digit.")
    if not any(c in string.punctuation for c in password):
        suggestions.append("Add at least one special character (e.g., !, @, #, $).")

    # Common password suggestion
    if password in common:
        suggestions.append("Avoid using common passwords.")

    # Entropy suggestion
    entropy = calculate_entropy(password)
    if entropy < 40:
        suggestions.append("Increase password complexity for higher entropy (more unpredictability).")

    return suggestions

def evaluate_password(password, common, policy):
    if check_common(password, common):
        return "Password is common. Strength: Weak"
    types_ok, types_msg = check_char_type(password, policy)
    length_ok, length_msg = check_length(password, policy)
    score = 0
    if types_ok:
        score += 1
    if length_ok:
        score += 1

    category = get_strength_category(score)
    entropy = calculate_entropy(password)
    crack_time_seconds = estimate_crack_time_seconds(entropy)
    seconds_per_year = 60 * 60 * 24 * 365.25
    crack_time_years = crack_time_seconds / seconds_per_year

    suggestions = get_password_suggestions(password, common) if category != "Strong" else []

    result = (f"Password strength: {category}\n"
              f"Entropy: {entropy:.2f} bits\n"
              f"Estimated time to crack {crack_time_years:.2e} years")

    if suggestions:
        result += "\nSuggestions:\n- " + "\n- ".join(suggestions)
    return result      

def main():
    policy = get_user_policy()
    password = get_password_from_user()
    result = evaluate_password(password, common, policy)
    print(result)


if __name__ == "__main__":
    main()
   

