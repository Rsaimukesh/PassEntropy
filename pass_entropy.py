#!/usr/bin/env python3
"""
PassEntropy - Password Strength Checker
Analyzes password strength and estimates time to crack
"""

import math
import re
from enum import Enum


class PasswordStrength(Enum):
    """Password strength levels"""
    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    MODERATE = "Moderate"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"


class PasswordAnalyzer:
    """Analyzes password strength and calculates time to crack"""
    
    # Assumed number of attempts per second (for a typical attacker)
    # This is conservative; modern GPUs can do billions per second
    ATTEMPTS_PER_SECOND = 1_000_000_000  # 1 billion attempts/sec
    
    def __init__(self, password):
        """
        Initialize the analyzer with a password
        
        Args:
            password: The password string to analyze
        """
        self.password = password
        self.length = len(password)
        self.charset_size = self._calculate_charset_size()
        self.entropy = self._calculate_entropy()
        self.strength = self._determine_strength()
        self.time_to_crack = self._estimate_time_to_crack()
    
    def _calculate_charset_size(self):
        """
        Calculate the character set size based on password composition
        
        Returns:
            int: The size of the character set used
        """
        charset_size = 0
        
        # Check for lowercase letters (a-z)
        if re.search(r'[a-z]', self.password):
            charset_size += 26
        
        # Check for uppercase letters (A-Z)
        if re.search(r'[A-Z]', self.password):
            charset_size += 26
        
        # Check for digits (0-9)
        if re.search(r'\d', self.password):
            charset_size += 10
        
        # Check for special characters
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', self.password):
            charset_size += 32  # Common special characters
        
        # Check for spaces
        if ' ' in self.password:
            charset_size += 1
        
        return max(charset_size, 1)  # Minimum 1 to avoid log(0)
    
    def _calculate_entropy(self):
        """
        Calculate password entropy in bits
        Entropy = log2(charset_size^length)
        
        Returns:
            float: Entropy in bits
        """
        if self.length == 0:
            return 0
        
        # Entropy formula: log2(N^L) where N is charset size, L is length
        entropy = self.length * math.log2(self.charset_size)
        return entropy
    
    def _determine_strength(self):
        """
        Determine password strength based on entropy
        
        Returns:
            PasswordStrength: The strength level
        """
        if self.entropy < 28:
            return PasswordStrength.VERY_WEAK
        elif self.entropy < 36:
            return PasswordStrength.WEAK
        elif self.entropy < 60:
            return PasswordStrength.MODERATE
        elif self.entropy < 128:
            return PasswordStrength.STRONG
        else:
            return PasswordStrength.VERY_STRONG
    
    def _estimate_time_to_crack(self):
        """
        Estimate time to crack the password based on entropy
        Assumes brute-force attack
        
        Returns:
            dict: Time breakdown with seconds and human-readable format
        """
        # Number of possible combinations
        combinations = 2 ** self.entropy
        
        # Average time to crack (assuming we find it halfway through)
        avg_attempts = combinations / 2
        
        # Time in seconds
        seconds = avg_attempts / self.ATTEMPTS_PER_SECOND
        
        return {
            'seconds': seconds,
            'readable': self._format_time(seconds)
        }
    
    def _format_time(self, seconds):
        """
        Format time in seconds to human-readable format
        
        Args:
            seconds: Time in seconds
            
        Returns:
            str: Human-readable time format
        """
        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{seconds:.2f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.2f} minutes"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.2f} hours"
        elif seconds < 31536000:
            days = seconds / 86400
            return f"{days:.2f} days"
        elif seconds < 31536000 * 100:
            years = seconds / 31536000
            return f"{years:.2f} years"
        elif seconds < 31536000 * 1000:
            years = seconds / 31536000
            return f"{years:.0f} years"
        elif seconds < 31536000 * 1000000:
            years = seconds / 31536000
            return f"{years:.2e} years"
        else:
            return "Centuries (practically unbreakable)"
    
    def get_analysis(self):
        """
        Get complete password analysis
        
        Returns:
            dict: Complete analysis results
        """
        return {
            'password_length': self.length,
            'charset_size': self.charset_size,
            'entropy_bits': round(self.entropy, 2),
            'strength': self.strength.value,
            'time_to_crack': self.time_to_crack['readable'],
            'time_seconds': self.time_to_crack['seconds'],
            'character_types': self._get_character_types()
        }
    
    def _get_character_types(self):
        """
        Get the types of characters used in the password
        
        Returns:
            dict: Boolean flags for each character type
        """
        return {
            'lowercase': bool(re.search(r'[a-z]', self.password)),
            'uppercase': bool(re.search(r'[A-Z]', self.password)),
            'digits': bool(re.search(r'\d', self.password)),
            'special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', self.password)),
            'spaces': ' ' in self.password
        }
    
    def get_recommendations(self):
        """
        Get recommendations to improve password strength
        
        Returns:
            list: List of recommendations
        """
        recommendations = []
        char_types = self._get_character_types()
        
        if self.length < 8:
            recommendations.append("Use at least 8 characters (12+ recommended)")
        elif self.length < 12:
            recommendations.append("Consider using 12 or more characters for better security")
        
        if not char_types['lowercase']:
            recommendations.append("Add lowercase letters (a-z)")
        
        if not char_types['uppercase']:
            recommendations.append("Add uppercase letters (A-Z)")
        
        if not char_types['digits']:
            recommendations.append("Add numbers (0-9)")
        
        if not char_types['special']:
            recommendations.append("Add special characters (!@#$%^&*)")
        
        if self.strength in [PasswordStrength.VERY_WEAK, PasswordStrength.WEAK]:
            recommendations.append("Consider using a passphrase with multiple words")
        
        if not recommendations:
            recommendations.append("Your password is strong! Keep it safe and don't reuse it.")
        
        return recommendations


def main():
    """Main CLI interface"""
    print("=" * 60)
    print("PassEntropy - Password Strength Checker")
    print("=" * 60)
    print()
    
    password = input("Enter a password to analyze: ")
    
    if not password:
        print("Error: Password cannot be empty")
        return
    
    analyzer = PasswordAnalyzer(password)
    analysis = analyzer.get_analysis()
    
    print("\n" + "=" * 60)
    print("PASSWORD ANALYSIS RESULTS")
    print("=" * 60)
    print(f"Password Length:        {analysis['password_length']} characters")
    print(f"Character Set Size:     {analysis['charset_size']}")
    print(f"Entropy:                {analysis['entropy_bits']} bits")
    print(f"Strength:               {analysis['strength']}")
    print(f"Estimated Time to Crack: {analysis['time_to_crack']}")
    print()
    
    print("Character Types Used:")
    char_types = analysis['character_types']
    print(f"  ✓ Lowercase letters" if char_types['lowercase'] else "  ✗ Lowercase letters")
    print(f"  ✓ Uppercase letters" if char_types['uppercase'] else "  ✗ Uppercase letters")
    print(f"  ✓ Digits" if char_types['digits'] else "  ✗ Digits")
    print(f"  ✓ Special characters" if char_types['special'] else "  ✗ Special characters")
    
    recommendations = analyzer.get_recommendations()
    if recommendations:
        print("\n" + "-" * 60)
        print("RECOMMENDATIONS:")
        print("-" * 60)
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
    
    print("\n" + "=" * 60)
    print("Note: Time estimates assume a brute-force attack with")
    print("1 billion attempts per second. Modern hardware can be faster.")
    print("=" * 60)


if __name__ == "__main__":
    main()
