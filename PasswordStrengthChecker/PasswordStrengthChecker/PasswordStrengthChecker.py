
import string
from pathlib import Path


password = "fFgmDt8t4utfmffmfmfGGJJ887!"

score = 0

# Check character types
upper_case = any([1 if c in string.ascii_uppercase else 0 for c in password])
lower_case = any([1 if c in string.ascii_lowercase else 0 for c in password])
special = any([1 if c in string.punctuation else 0 for c in password])
digits = any([1 if c in string.digits else 0 for c in password])

characters = [upper_case, lower_case, special, digits]

if sum(characters) > 1:
    score += 1
if sum(characters) > 2:
    score += 2
if sum(characters) > 3:
    score += 3

# Check if common
script_dir = Path(__file__).parent

file_path = script_dir / 'passwords.txt'

with file_path.open('r') as f:
    common = f.read().splitlines()

if password in common:
    print("Password is common. Score: 0 / 10")
    exit()

# Check length
length = len(password)

if length > 8:
    score += 1
if length > 12:
    score += 1
if length > 17:
    score += 1
if length > 20:
    score += 1

if score < 4:
    print(f"Your password is quite weak! Score {str(score)} / 10")
elif score == 4:
    print(f"Your password is okay! Score: {str(score)} / 10")
elif score > 4 and score < 6:
    print(f"Your password is okay! Score: {str(score)} / 10")
elif score > 6:
    print(f"Your password is strong! Score: {str(score)} / 10")
    exit()
   

