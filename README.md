# PassEntropy

A comprehensive password strength analyzer that calculates entropy, keyspace, and estimated crack times for different attack scenarios.

## Features

- **Real-time Password Analysis** - Instant feedback as you type
- **Character Set Detection** - Automatically detects lowercase, uppercase, digits, and symbols
- **Entropy Calculation** - Calculates password entropy in bits using the formula: `length × log2(charset_size)`
- **Keyspace Visualization** - Shows the total number of possible combinations as `2^entropy`
- **Crack Time Estimates** - Displays time to crack for 4 different attacker scenarios:
  - Online / Rate-Limited (100 guesses/sec)
  - Single GPU / Weak Offline (10,000 guesses/sec)
  - Strong GPU Cluster (1 billion guesses/sec)
  - Huge Cluster / ASIC (100 billion guesses/sec)
- **Visual Strength Meter** - Color-coded strength indicator (Weak to Very Strong)
- **Security Tips** - Practical advice for password security
- **Weakness Detection** - Identifies common patterns, repeated characters, and weak passwords
- **Privacy-First** - All calculations performed locally in your browser

## Usage

Simply open `index.html` in your web browser and start typing a password. The tool will:

1. Detect the character sets used in your password
2. Calculate the entropy and keyspace
3. Show estimated crack times for different attack scenarios
4. Display a visual strength meter
5. Warn you about common weaknesses

## How It Works

### Entropy Calculation

The tool uses the standard formula for password entropy:

```
Entropy (bits) = password_length × log₂(charset_size)
```

Where charset_size is determined by:
- Lowercase letters (a-z): 26 characters
- Uppercase letters (A-Z): 26 characters
- Digits (0-9): 10 characters
- Symbols (!@#$%^&*...): 33 characters (common printable ASCII symbols)

### Crack Time Estimation

Average guesses needed = `2^(entropy - 1)` (on average, an attacker finds the password halfway through the keyspace)

Time to crack = `average_guesses / guesses_per_second`

### Strength Ratings

- **Very Weak** (< 28 bits): Easily crackable
- **Weak** (28-35 bits): Vulnerable to most attacks
- **Fair** (36-59 bits): Basic protection
- **Good** (60-79 bits): Good protection
- **Strong** (80-99 bits): Strong protection
- **Very Strong** (≥ 100 bits): Excellent protection

## Security Best Practices

1. **Use a password manager** to generate and store strong, unique passwords
2. **Enable 2FA** wherever possible for an additional layer of security
3. **Prefer passphrases** - longer passwords with multiple words are stronger
4. **Avoid common patterns** like sequential characters or keyboard patterns
5. **Never reuse passwords** across different accounts
6. **Update passwords regularly**, especially for sensitive accounts

## Privacy

This tool runs entirely in your browser using JavaScript. Your password is never sent to any server or stored anywhere. All calculations are performed locally on your device.

## License

MIT License
