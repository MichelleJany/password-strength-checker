
import math
import string
from pathlib import Path
import hashlib
import requests

# ===== Constants ====
DEFAULT_POLICY = {
    'min_length': 8,
    'require_upper': True,
    'require_lower': True,
    'require_digit': True,
    'require_special': True
}

# ==== Load Common Passwords ====
script_dir = Path(__file__).parent
file_path = script_dir / 'passwords.txt'
with file_path.open('r') as f:
    common = f.read().splitlines()

# ==== User Input Functions ====
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

# ==== Password Checks ====
def check_common (password, common):
    # Check if common
    return password in common

def check_pwned_password(password):
    # Hash password with SHA-1
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    # Query HIBP API with first 5 characters
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "PasswordStrengthChecker"}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return False, 0

    hashes = (line.split(':') for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return True, int(count)
    return False, 0

def calculate_policy_score(password, policy):
    score = 0
    max_score = 0

    # Length
    max_score += 1
    if len(password) >= policy['min_length']:
        score += 1

    # Uppercase
    if policy['require_upper']:
        max_score += 1
        if any(c.isupper() for c in password):
            score += 1

    # Lowercase
    if policy['require_lower']:
        max_score += 1
        if any(c.islower() for c in password):
            score += 1

    # Digit
    if policy['require_digit']:
        max_score += 1
        if any(c.isdigit() for c in password):
            score += 1

    # Special
    if policy['require_special']:
        max_score += 1
        if any(c in string.punctuation for c in password):
            score += 1

    return score, max_score

def get_strength_category(score, max_score, entropy, crack_time_years):
    ratio = score / max_score if max_score else 0
    # Realistic thresholds
    if entropy < 40 or crack_time_years < 1:
        return "Weak"
    if ratio < 0.5:
        return "Weak"
    elif ratio < 0.8:
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

    if charset_size == 0:
        return 0
    return len(password) * math.log2(charset_size)

def estimate_crack_time_seconds(entropy_bits, guesses_per_second=1e10):
    return 2 ** entropy_bits / guesses_per_second

# ==== Suggestions & Advice ====
def get_password_suggestions(password, common, policy):
    suggestions = []

    # Length suggestions
    if len(password) < policy['min_length']:
        suggestions.append(f"Make your password at least {policy['min_length']} characters long.")
    if policy['require_lower'] and not any(c.islower() for c in password):
        suggestions.append("Add at least one lowercase letter.")
    if policy['require_upper'] and not any(c.isupper() for c in password):
        suggestions.append("Add at least one uppercase letter.")
    if policy['require_digit'] and not any(c.isdigit() for c in password):
        suggestions.append("Add at least one digit.")
    if policy['require_special'] and not any(c in string.punctuation for c in password):
        suggestions.append("Add at least one special character (e.g., !, @, #, $).")

    # Common password suggestion
    if password in common:
        suggestions.append("Avoid using common passwords.")

    # Entropy suggestion
    entropy = calculate_entropy(password)
    if entropy < 40:
        suggestions.append("Increase password complexity for higher entropy (more unpredictability).")

    return suggestions

def get_best_practice(password, policy):
    advice = []
    if not policy['require_lower'] and not any(c.islower() for c in password):
        advice.append("Consider adding lowercase letters for even stronger security.")
    if not policy['require_upper'] and not any(c.isupper() for c in password):
        advice.append("Consider adding uppercase letters for even stronger security.")
    if not policy['require_digit'] and not any(c.isdigit() for c in password):
        advice.append("Consider adding digits for even stronger security.")
    if not policy['require_special'] and not any(c in string.punctuation for c in password):
        advice.append("Consider adding special characters for even stronger security.")
    return advice

def format_crack_time(crack_time_years):
    try:
        if crack_time_years > 1e12:
            trillions = crack_time_years / 1e12
            return f"{trillions:,.2f} trillion years"
        elif crack_time_years > 1e9:
            billions = crack_time_years / 1e9
            return f"{billions:,.2f} billion years"
        elif crack_time_years > 1e6:
            millions = crack_time_years / 1e6
            return f"{millions:,.2f} million years"
        elif crack_time_years > 1e3:
            thousands = crack_time_years / 1e3
            return f"{thousands:,.2f} thousand years"
        else:
            return f"{int(crack_time_years):,} years"
    except Exception:
        return str(crack_time_years) + " years"
       

# ==== Main Evaluation ====
def evaluate_password(password, common, policy):
    result_lines = []
    if check_common(password, common):
        result_lines.append("WARNING: This password is on a common passwords list.")

    breached, count = check_pwned_password(password)
    if breached:
        result_lines.append(f"WARNING: This password has appeared in {count:,} data breaches! Choose another.")
    else:
        result_lines.append("Good news: This password was not found in known breaches.")

    score, max_score = calculate_policy_score(password, policy)
    entropy = calculate_entropy(password)
    crack_time_seconds = estimate_crack_time_seconds(entropy)
    seconds_per_year = 60 * 60 * 24 * 365.25
    crack_time_years = crack_time_seconds / seconds_per_year
    crack_time_str = format_crack_time(crack_time_years)

    category = get_strength_category(score, max_score, entropy, crack_time_years)
    suggestions = get_password_suggestions(password, common, policy) if category != "Strong" else []
    best_practice = get_best_practice(password, policy)

    result_lines.append(f"\nPassword Strength: {category}")
    result_lines.append(f"Score: {score} / {max_score}")
    result_lines.append(f"Entropy: {entropy:.2f} bits\n")
    result_lines.append(f"Estimated time to crack: {crack_time_str}")

    if suggestions:
        result_lines.append("Suggestions:\n- " + "\n- ".join(suggestions))
    if best_practice:
        result_lines.append("Best practice advice:\n- " + "\n- ".join(best_practice))

    return "\n".join(result_lines)

def main():
    policy = get_user_policy()
    password = get_password_from_user()
    result = evaluate_password(password, common, policy)
    print(result)


if __name__ == "__main__":
    main()
   

