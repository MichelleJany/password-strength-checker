
from pickletools import read_stringnl_noescape_pair
import math
import string
from pathlib import Path
import os

# Constants
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

def check_char_type (password):
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

def check_length(password):
    return sum(1 for threshold in LENGTH_THRESHOLDS if len(password) > threshold)

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

def evaluate_password(password, common):
    if check_common(password, common):
        return "Password is common. Strength: Weak"
    score = check_char_type(password)
    score += check_length(password)
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
    password = get_password_from_user()
    result = evaluate_password(password, common)
    print(result)

if __name__ == "__main__":
    main()
   

