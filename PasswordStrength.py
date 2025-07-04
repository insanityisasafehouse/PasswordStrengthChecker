import re

# --- Configuration ---
# Define minimum lengths for different strength levels.
MIN_LENGTH_WEAK = 6
MIN_LENGTH_MEDIUM = 8
MIN_LENGTH_STRONG = 12

# --- Helper Functions ---

def check_password_strength(password: str) -> str:
    """
    Evaluates the strength of a given password based on various criteria.

    Args:
        password (str): The password string to evaluate.

    Returns:
        str: A string indicating the strength (e.g., "Very Weak", "Weak", "Medium", "Strong", "Very Strong").
    """
    score = 0
    feedback = []

    # 1. Length Check
    length = len(password)
    if length >= MIN_LENGTH_STRONG:
        score += 3
    elif length >= MIN_LENGTH_MEDIUM:
        score += 2
    elif length >= MIN_LENGTH_WEAK:
        score += 1
    else:
        feedback.append(f"Password is too short. Minimum recommended length is {MIN_LENGTH_MEDIUM} characters.")

    # 2. Character Type Checks using Regular Expressions
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?`~]', password))

    char_types = 0
    if has_lowercase:
        char_types += 1
    if has_uppercase:
        char_types += 1
    if has_digit:
        char_types += 1
    if has_special:
        char_types += 1

    score += char_types # Add score based on diversity of character types

    if char_types < 3:
        feedback.append("Include a mix of uppercase and lowercase letters, numbers, and special characters.")
    if not has_lowercase:
        feedback.append("Add lowercase letters.")
    if not has_uppercase:
        feedback.append("Add uppercase letters.")
    if not has_digit:
        feedback.append("Add numbers.")
    if not has_special:
        feedback.append("Add special characters (e.g., !@#$%^&*).")

    # 3. Common Password Check (Simple example - could be expanded with a large dictionary)
    # This is a very basic check. In a real-world scenario, you'd use a large blacklist.
    common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
    if password.lower() in common_passwords:
        score = 0 # Immediately make it very weak if it's a common password
        feedback.append("This is a very common and easily guessable password.")

    # 4. Sequential/Repetitive Characters (Basic check)
    if re.search(r'(.)\1\1', password): # Checks for 3 or more repeating characters
        score -= 1
        feedback.append("Avoid using repeating characters (e.g., 'aaa').")
    if re.search(r'abc|123|def|456', password, re.IGNORECASE): # Checks for simple sequences
        score -= 1
        feedback.append("Avoid using common sequences (e.g., 'abc', '123').")

    # --- Determine Strength Level ---
    if score >= 8:
        strength = "Very Strong"
    elif score >= 6:
        strength = "Strong"
    elif score >= 4:
        strength = "Medium"
    elif score >= 2:
        strength = "Weak"
    else:
        strength = "Very Weak"

    return strength, feedback

def main():
    """
    Main function to run the password strength checker.
    Prompts the user to enter a password and displays its strength and feedback.
    """
    print("-" * 50)
    print("Password Strength Checker")
    print("-" * 50)

    while True:
        password = input("Enter a password to check (or 'q' to quit): ")
        if password.lower() == 'q':
            break

        if not password:
            print("Please enter a password.")
            continue

        strength, feedback = check_password_strength(password)
        print(f"\nPassword: '{password}'")
        print(f"Strength: {strength}")

        if feedback:
            print("Suggestions for improvement:")
            for item in feedback:
                print(f"- {item}")
        else:
            print("Great job! Your password is strong.")
        print("-" * 50)

if __name__ == "__main__":
    main()
