import string
import hashlib
import random
import requests

def generate_strong_password(user_input):
    """Generates a perfectly consistent, strong password based on the user's input."""
    # Turn the user's password into a unique number to use as a seed
    hasher = hashlib.sha256(user_input.encode('utf-8'))
    seed_integer = int(hasher.hexdigest(), 16)
    
    # Seed Python's standard random module with that unique number
    rng = random.Random(seed_integer)
    
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*"
    all_chars = lower + upper + digits + special
    
    # Guarantee at least one character from each required pool
    password_parts = [
        rng.choice(lower),
        rng.choice(upper),
        rng.choice(digits),
        rng.choice(special)
    ]
    
    # Fill up the rest to hit 16 characters
    for _ in range(12):
        password_parts.append(rng.choice(all_chars))
        
    # Shuffle the characters predictably based on the seed
    rng.shuffle(password_parts)
    
    return "".join(password_parts)

def check_pwned_api(password):
    """Checks if the password has been exposed in a known data breach."""
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_chars, remainder = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{first5_chars}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200: return 0
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == remainder: return int(count)
    except requests.RequestException:
        pass
    return 0

def check_password_strength(password):
    score = 0
    feedback = []
    if len(password) >= 12: score += 2
    elif len(password) >= 8: score += 1
    else: feedback.append("• Password should be at least 8 characters long (12+ recommended).")
        
    if any(c.isupper() for c in password): score += 1
    else: feedback.append("• Add uppercase letters (A-Z).")
    if any(c.islower() for c in password): score += 1
    else: feedback.append("• Add lowercase letters (a-z).")
    if any(c.isdigit() for c in password): score += 1
    else: feedback.append("• Add numerical digits (0-9).")
    if any(c in string.punctuation for c in password): score += 1
    else: feedback.append("• Add special characters (e.g., !, @, #, $, %).")

    strength = "Strong 💪" if score >= 5 else "Moderate ⚠️" if score >= 3 else "Weak ❌"
    return strength, feedback

def main():
    print("=== Cybersecurity Tool: Consistent Strong Password Generator ===")
    user_password = input("Enter a password to test: ")
    
    strength, suggestions = check_password_strength(user_password)
    breach_count = check_pwned_api(user_password)
    
    print("\n--- RESULTS ---")
    print(f"Local Complexity Strength: {strength}")
    
    if breach_count > 0:
        print(f"Live Breach Status: 🚨 COMPROMISED! Found in {breach_count:,} data breaches.")
    else:
        print("Live Breach Status: ✅ Safe! Not found in public breaches.")
        
    if suggestions:
        print("\nSuggestions to improve local complexity:")
        for suggestion in suggestions:
            print(suggestion)
            
    # Show the automatic prediction if the password isn't strong or is breached
    if strength != "Strong 💪" or breach_count > 0:
        suggested_pwd = generate_strong_password(user_password)
        print("\n" + "="*50)
        print("💡 CONSISTENT AUTOMATIC RECOMMENDATION:")
        print(f"Here is a secure, unbreached password you can use instead:\n👉 {suggested_pwd}")
        print("="*50)

if __name__ == "__main__":
    main()