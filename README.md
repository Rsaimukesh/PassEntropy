# PassEntropy

A comprehensive password strength checker that analyzes password security and estimates the time required to crack passwords using brute-force attacks.

## Features

- **Password Strength Analysis**: Evaluates password strength based on entropy calculation
- **Time-to-Crack Estimation**: Provides estimated time to break passwords using brute-force attacks
- **Character Type Detection**: Identifies the types of characters used (lowercase, uppercase, digits, special characters)
- **Entropy Calculation**: Calculates password entropy in bits
- **Security Recommendations**: Offers actionable suggestions to improve password strength
- **Interactive CLI**: Easy-to-use command-line interface

## Installation

No external dependencies required! Just Python 3.6 or higher.

```bash
git clone https://github.com/Rsaimukesh/PassEntropy.git
cd PassEntropy
```

## Usage

### Command Line Interface

Run the interactive password analyzer:

```bash
python3 pass_entropy.py
```

You'll be prompted to enter a password, and the tool will provide a comprehensive analysis.

### Example Output

```
============================================================
PassEntropy - Password Strength Checker
============================================================

Enter a password to analyze: MyP@ssw0rd123!

============================================================
PASSWORD ANALYSIS RESULTS
============================================================
Password Length:        14 characters
Character Set Size:     94
Entropy:                91.76 bits
Strength:               Strong
Estimated Time to Crack: Centuries (practically unbreakable)

Character Types Used:
  ✓ Lowercase letters
  ✓ Uppercase letters
  ✓ Digits
  ✓ Special characters

------------------------------------------------------------
RECOMMENDATIONS:
------------------------------------------------------------
1. Your password is strong! Keep it safe and don't reuse it.

============================================================
Note: Time estimates assume a brute-force attack with
1 billion attempts per second. Modern hardware can be faster.
============================================================
```

### Using as a Python Module

You can also import and use the `PasswordAnalyzer` class in your own Python scripts:

```python
from pass_entropy import PasswordAnalyzer

# Analyze a password
analyzer = PasswordAnalyzer("MyP@ssw0rd123!")

# Get the complete analysis
analysis = analyzer.get_analysis()
print(f"Strength: {analysis['strength']}")
print(f"Entropy: {analysis['entropy_bits']} bits")
print(f"Time to crack: {analysis['time_to_crack']}")

# Get recommendations
recommendations = analyzer.get_recommendations()
for rec in recommendations:
    print(f"- {rec}")
```

## How It Works

### Entropy Calculation

Password entropy is calculated using the formula:
```
Entropy = L × log₂(N)
```
Where:
- L = Password length
- N = Character set size

The character set size is determined by the types of characters used:
- Lowercase letters (a-z): 26 characters
- Uppercase letters (A-Z): 26 characters
- Digits (0-9): 10 characters
- Special characters: 32 common special characters

### Strength Levels

| Strength Level | Entropy Range | Description |
|----------------|---------------|-------------|
| Very Weak | < 28 bits | Easily cracked in seconds |
| Weak | 28-35 bits | Can be cracked in minutes to hours |
| Moderate | 36-59 bits | Takes days to weeks to crack |
| Strong | 60-127 bits | Takes years to centuries to crack |
| Very Strong | ≥ 128 bits | Practically unbreakable |

### Time-to-Crack Estimation

The tool estimates the time to crack a password assuming:
- Brute-force attack methodology
- 1 billion attempts per second (conservative estimate)
- Average case: finding the password halfway through all possible combinations

**Note**: Modern GPU-based cracking systems can perform significantly more attempts per second, so real-world times may be lower for weaker passwords.

## Testing

Run the comprehensive test suite:

```bash
python3 -m unittest test_pass_entropy.py -v
```

The test suite includes 24 test cases covering:
- Character set detection
- Entropy calculation accuracy
- Strength level classification
- Time-to-crack estimation
- Recommendation generation
- Edge cases (empty passwords, single character types, etc.)

## Security Considerations

- **Never transmit or store passwords in plain text**: This tool is for educational and analysis purposes only
- **Use unique passwords**: Never reuse passwords across different services
- **Enable 2FA**: Two-factor authentication adds an additional security layer
- **Use a password manager**: Consider using a reputable password manager to generate and store strong passwords
- **Regular updates**: Change passwords periodically, especially for sensitive accounts

## Examples

### Weak Password
```
Password: "password"
Strength: Weak
Entropy: 37.60 bits
Time to Crack: 1.24 minutes
```

### Moderate Password
```
Password: "password123"
Strength: Moderate
Entropy: 56.60 bits
Time to Crack: 2.65 days
```

### Strong Password
```
Password: "P@ssw0rd123!"
Strength: Strong
Entropy: 78.85 bits
Time to Crack: 9.56 million years
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available for educational purposes.

## Author

Rsaimukesh

## Disclaimer

This tool is intended for educational purposes and to help users understand password security. Always follow your organization's security policies and best practices for password management.

