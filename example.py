#!/usr/bin/env python3
"""
Example script demonstrating the use of PassEntropy as a Python module
"""

from pass_entropy import PasswordAnalyzer

# Example passwords to analyze
example_passwords = [
    "password",
    "Password123",
    "P@ssw0rd123!",
    "MyV3ry$tr0ng&C0mpl3xP@ssw0rd!2024",
    "abc",
    "12345678"
]

print("=" * 70)
print("PassEntropy - Password Analysis Examples")
print("=" * 70)
print()

for password in example_passwords:
    print(f"Analyzing: '{password}'")
    print("-" * 70)
    
    analyzer = PasswordAnalyzer(password)
    analysis = analyzer.get_analysis()
    
    print(f"  Length:         {analysis['password_length']} characters")
    print(f"  Charset Size:   {analysis['charset_size']}")
    print(f"  Entropy:        {analysis['entropy_bits']} bits")
    print(f"  Strength:       {analysis['strength']}")
    print(f"  Time to Crack:  {analysis['time_to_crack']}")
    
    # Show character types
    char_types = analysis['character_types']
    types_used = []
    if char_types['lowercase']: types_used.append("lowercase")
    if char_types['uppercase']: types_used.append("uppercase")
    if char_types['digits']: types_used.append("digits")
    if char_types['special']: types_used.append("special")
    
    print(f"  Character Types: {', '.join(types_used)}")
    
    # Show first recommendation
    recommendations = analyzer.get_recommendations()
    if recommendations:
        print(f"  Top Tip:        {recommendations[0]}")
    
    print()

print("=" * 70)
print("Tip: The stronger your password, the longer it takes to crack!")
print("=" * 70)
