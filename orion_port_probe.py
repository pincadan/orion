def analyze_text(text):
    # Initialize counters for different types of characters
    uppercase_count = 0
    lowercase_count = 0
    digit_count = 0
    special_count = 0

    # Iterate through each character in the text
    for char in text:
        if char.isupper():
            uppercase_count += 1
        elif char.islower():
            lowercase_count += 1
        elif char.isdigit():
            digit_count += 1
        else:
            special_count += 1

    # Calculate the total number of characters
    total_count = uppercase_count + lowercase_count + digit_count + special_count

    # Calculate the percentage of each type of character
    uppercase_percent = (uppercase_count / total_count) * 100
    lowercase_percent = (lowercase_count / total_count) * 100
    digit_percent = (digit_count / total_count) * 100
    special_percent = (special_count / total_count) * 100

    # Return the results as a dictionary
    return {
        'uppercase': uppercase_percent,
        'lowercase': lowercase_percent,
        'digits': digit_percent,
        'special': special_percent
    }

# Example usage
text = "Hello, World!"
result = analyze_text(text)
print(result)