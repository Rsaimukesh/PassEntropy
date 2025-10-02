#!/usr/bin/env python3
"""
Unit tests for PassEntropy password strength checker
"""

import unittest
from pass_entropy import PasswordAnalyzer, PasswordStrength


class TestPasswordAnalyzer(unittest.TestCase):
    """Test cases for PasswordAnalyzer class"""
    
    def test_empty_password(self):
        """Test with empty password"""
        analyzer = PasswordAnalyzer("")
        self.assertEqual(analyzer.length, 0)
        self.assertEqual(analyzer.entropy, 0)
    
    def test_lowercase_only(self):
        """Test password with only lowercase letters"""
        analyzer = PasswordAnalyzer("password")
        self.assertEqual(analyzer.charset_size, 26)
        analysis = analyzer.get_analysis()
        self.assertTrue(analysis['character_types']['lowercase'])
        self.assertFalse(analysis['character_types']['uppercase'])
        self.assertFalse(analysis['character_types']['digits'])
        self.assertFalse(analysis['character_types']['special'])
    
    def test_mixed_case(self):
        """Test password with mixed case"""
        analyzer = PasswordAnalyzer("Password")
        self.assertEqual(analyzer.charset_size, 52)
        analysis = analyzer.get_analysis()
        self.assertTrue(analysis['character_types']['lowercase'])
        self.assertTrue(analysis['character_types']['uppercase'])
    
    def test_with_digits(self):
        """Test password with letters and digits"""
        analyzer = PasswordAnalyzer("password123")
        self.assertEqual(analyzer.charset_size, 36)
        analysis = analyzer.get_analysis()
        self.assertTrue(analysis['character_types']['lowercase'])
        self.assertTrue(analysis['character_types']['digits'])
    
    def test_with_special_chars(self):
        """Test password with special characters"""
        analyzer = PasswordAnalyzer("p@ssw0rd!")
        self.assertEqual(analyzer.charset_size, 68)  # 26 + 10 + 32
        analysis = analyzer.get_analysis()
        self.assertTrue(analysis['character_types']['lowercase'])
        self.assertTrue(analysis['character_types']['digits'])
        self.assertTrue(analysis['character_types']['special'])
    
    def test_full_charset(self):
        """Test password with all character types"""
        analyzer = PasswordAnalyzer("P@ssw0rd!")
        self.assertEqual(analyzer.charset_size, 94)  # 26 + 26 + 10 + 32
        analysis = analyzer.get_analysis()
        self.assertTrue(analysis['character_types']['lowercase'])
        self.assertTrue(analysis['character_types']['uppercase'])
        self.assertTrue(analysis['character_types']['digits'])
        self.assertTrue(analysis['character_types']['special'])
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        # For "password" (8 chars, 26 charset): 8 * log2(26) ≈ 37.6 bits
        analyzer = PasswordAnalyzer("password")
        self.assertAlmostEqual(analyzer.entropy, 37.6, places=1)
    
    def test_strength_very_weak(self):
        """Test very weak password detection"""
        analyzer = PasswordAnalyzer("pass")
        self.assertEqual(analyzer.strength, PasswordStrength.VERY_WEAK)
    
    def test_strength_weak(self):
        """Test weak password detection"""
        analyzer = PasswordAnalyzer("passwo")
        self.assertEqual(analyzer.strength, PasswordStrength.WEAK)
    
    def test_strength_moderate(self):
        """Test moderate password detection"""
        analyzer = PasswordAnalyzer("password123")
        self.assertEqual(analyzer.strength, PasswordStrength.MODERATE)
    
    def test_strength_strong(self):
        """Test strong password detection"""
        analyzer = PasswordAnalyzer("P@ssw0rd123!")
        self.assertEqual(analyzer.strength, PasswordStrength.STRONG)
    
    def test_strength_very_strong(self):
        """Test very strong password detection"""
        # Very long password with high entropy (128+ bits)
        analyzer = PasswordAnalyzer("MyV3ry$tr0ng&C0mpl3xP@ssw0rd!2024")
        self.assertEqual(analyzer.strength, PasswordStrength.VERY_STRONG)
    
    def test_time_to_crack_instant(self):
        """Test instant crack time for very weak passwords"""
        analyzer = PasswordAnalyzer("a")
        time_readable = analyzer.time_to_crack['readable']
        # Very weak password should crack instantly or in seconds
        self.assertTrue("instant" in time_readable.lower() or "second" in time_readable.lower())
    
    def test_time_to_crack_format(self):
        """Test time to crack formatting"""
        analyzer = PasswordAnalyzer("P@ssw0rd123!")
        time_info = analyzer.time_to_crack
        self.assertIn('seconds', time_info)
        self.assertIn('readable', time_info)
        self.assertIsInstance(time_info['seconds'], float)
        self.assertIsInstance(time_info['readable'], str)
    
    def test_recommendations_weak_password(self):
        """Test recommendations for weak password"""
        analyzer = PasswordAnalyzer("pass")
        recommendations = analyzer.get_recommendations()
        self.assertGreater(len(recommendations), 0)
        # Should recommend longer password
        self.assertTrue(any('8 characters' in rec for rec in recommendations))
    
    def test_recommendations_missing_uppercase(self):
        """Test recommendations when uppercase is missing"""
        analyzer = PasswordAnalyzer("password123")
        recommendations = analyzer.get_recommendations()
        self.assertTrue(any('uppercase' in rec.lower() for rec in recommendations))
    
    def test_recommendations_missing_special(self):
        """Test recommendations when special chars are missing"""
        analyzer = PasswordAnalyzer("Password123")
        recommendations = analyzer.get_recommendations()
        self.assertTrue(any('special' in rec.lower() for rec in recommendations))
    
    def test_recommendations_strong_password(self):
        """Test recommendations for strong password"""
        analyzer = PasswordAnalyzer("MyV3ry$tr0ng&P@ss")
        recommendations = analyzer.get_recommendations()
        # Should have minimal or positive recommendations
        self.assertTrue(any('strong' in rec.lower() for rec in recommendations))
    
    def test_analysis_structure(self):
        """Test the structure of analysis output"""
        analyzer = PasswordAnalyzer("Test123!")
        analysis = analyzer.get_analysis()
        
        # Check all required keys are present
        self.assertIn('password_length', analysis)
        self.assertIn('charset_size', analysis)
        self.assertIn('entropy_bits', analysis)
        self.assertIn('strength', analysis)
        self.assertIn('time_to_crack', analysis)
        self.assertIn('time_seconds', analysis)
        self.assertIn('character_types', analysis)
        
        # Check character_types structure
        char_types = analysis['character_types']
        self.assertIn('lowercase', char_types)
        self.assertIn('uppercase', char_types)
        self.assertIn('digits', char_types)
        self.assertIn('special', char_types)
        self.assertIn('spaces', char_types)
    
    def test_password_with_spaces(self):
        """Test password containing spaces"""
        analyzer = PasswordAnalyzer("my password 123")
        analysis = analyzer.get_analysis()
        self.assertTrue(analysis['character_types']['spaces'])
        # Spaces should add to charset
        self.assertGreater(analyzer.charset_size, 36)
    
    def test_numeric_only_password(self):
        """Test password with only numbers"""
        analyzer = PasswordAnalyzer("123456")
        self.assertEqual(analyzer.charset_size, 10)
        analysis = analyzer.get_analysis()
        self.assertFalse(analysis['character_types']['lowercase'])
        self.assertTrue(analysis['character_types']['digits'])
    
    def test_special_characters_detection(self):
        """Test detection of various special characters"""
        special_chars = "!@#$%^&*()_+-=[]{}|;:',.<>?/\\`~"
        for char in special_chars:
            analyzer = PasswordAnalyzer(f"pass{char}")
            analysis = analyzer.get_analysis()
            self.assertTrue(analysis['character_types']['special'], 
                          f"Failed to detect special char: {char}")


class TestPasswordStrengthLevels(unittest.TestCase):
    """Test password strength level classifications"""
    
    def test_strength_levels_order(self):
        """Test that stronger passwords have higher entropy"""
        weak = PasswordAnalyzer("pass")
        moderate = PasswordAnalyzer("password123")
        strong = PasswordAnalyzer("P@ssw0rd123!")
        
        self.assertLess(weak.entropy, moderate.entropy)
        self.assertLess(moderate.entropy, strong.entropy)
    
    def test_length_impact_on_strength(self):
        """Test that longer passwords are stronger"""
        short = PasswordAnalyzer("P@ss1")
        medium = PasswordAnalyzer("P@ssw0rd1")
        long = PasswordAnalyzer("P@ssw0rd123456!")
        
        self.assertLess(short.entropy, medium.entropy)
        self.assertLess(medium.entropy, long.entropy)


if __name__ == '__main__':
    unittest.main()
