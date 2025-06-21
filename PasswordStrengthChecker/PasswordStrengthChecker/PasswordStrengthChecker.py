
from pickletools import read_stringnl_noescape_pair
import string
from pathlib import Path

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

password = "fFgmDt8t4utfmffmfmf!!!---ttzujfffFF::GGJJ887!"

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

def evaluate_password(password, common):
    if check_common(password, common):
        return "Password is common. Strength: Weak"
    score = check_char_type(password)
    score += check_length(password)
    category = get_strength_category(score)
    return f"Password strength: {category}"

def main():
    password = get_password_from_user()
    result = evaluate_password(password, common)
    print(result)

if __name__ == "__main__":
    main()
   

