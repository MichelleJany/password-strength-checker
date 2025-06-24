
import math
import string
from pathlib import Path
import hashlib
import requests
import tkinter as tk
from tkinter import messagebox
import re

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

# ==== Password Checks ====
def check_common (password, common):
    # Check if common
    return password in common

def check_pwned_password(password):
    # Hash password with SHA-1
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
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
    result_lines.append(f"Estimated time to crack: {crack_time_str}\n")

    if suggestions:
        result_lines.append("Suggestions:\n- " + "\n- ".join(suggestions))
    if best_practice:
        result_lines.append("Best practice advice:\n- " + "\n- ".join(best_practice))

    return "\n".join(result_lines)

# ==== Tkinter ====
root = tk.Tk()
root.title("Password Checker")
root.geometry("400x400")

password_var = tk.StringVar()

label = tk.Label(root, text="Enter Password:")
label.pack(pady=10)

password_entry = tk.Entry(root, textvariable=password_var, width=30, show='*')
password_entry.pack(pady=5)

show_password_var = tk.BooleanVar()
def toggle_password_visibility():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

show_password_check = tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password_visibility)
show_password_check.pack(pady=5)

result_label = tk.Label(root, text="", wraplength=380, justify="left")
result_label.pack(pady=10)

def check_password(event=None):
    pw = password_var.get()
    result = evaluate_password(pw, common, DEFAULT_POLICY)
    result_label.config(text=result)

password_entry.bind('<Return>', check_password)
check_button = tk.Button(root, text="Check Password", command=check_password)
check_button.pack()
    
root.mainloop()
