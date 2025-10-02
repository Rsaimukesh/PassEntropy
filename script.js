// Password Entropy Calculator

// Character set sizes
const CHARSET_SIZES = {
    lowercase: 26,
    uppercase: 26,
    digits: 10,
    symbols: 33  // Common ASCII symbols
};

// Attacker speeds (guesses per second)
const ATTACKER_SPEEDS = {
    online: 100,
    gpu: 10000,
    cluster: 1000000000,
    asic: 100000000000
};

// Get DOM elements
const passwordInput = document.getElementById('password');
const togglePasswordBtn = document.getElementById('togglePassword');
const resultsSection = document.getElementById('results');
const warningsSection = document.getElementById('warnings');
const warningsList = document.getElementById('warningsList');

// Character set indicators
const lowercaseCheck = document.getElementById('lowercase-check');
const uppercaseCheck = document.getElementById('uppercase-check');
const digitsCheck = document.getElementById('digits-check');
const symbolsCheck = document.getElementById('symbols-check');

// Result displays
const lengthDisplay = document.getElementById('length');
const charsetSizeDisplay = document.getElementById('charsetSize');
const entropyDisplay = document.getElementById('entropy');
const keyspaceDisplay = document.getElementById('keyspace');
const strengthBar = document.getElementById('strengthBar');
const strengthLabel = document.getElementById('strengthLabel');

// Time displays
const timeOnline = document.getElementById('time-online');
const timeGpu = document.getElementById('time-gpu');
const timeCluster = document.getElementById('time-cluster');
const timeAsic = document.getElementById('time-asic');

// Toggle password visibility
togglePasswordBtn.addEventListener('click', () => {
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    togglePasswordBtn.querySelector('.eye-icon').textContent = type === 'password' ? '👁️' : '👁️‍🗨️';
});

// Main password analysis function
passwordInput.addEventListener('input', () => {
    const password = passwordInput.value;
    
    if (password.length === 0) {
        resetDisplay();
        return;
    }
    
    analyzePassword(password);
});

function analyzePassword(password) {
    // Detect character sets
    const charSets = detectCharacterSets(password);
    
    // Calculate charset size
    const charsetSize = calculateCharsetSize(charSets);
    
    // Calculate entropy
    const entropy = calculateEntropy(password.length, charsetSize);
    
    // Calculate keyspace
    const keyspace = entropy; // 2^entropy
    
    // Calculate average guesses (2^(entropy-1))
    const averageGuesses = Math.pow(2, entropy - 1);
    
    // Calculate time to crack for different scenarios
    const crackTimes = calculateCrackTimes(averageGuesses);
    
    // Detect weaknesses
    const warnings = detectWeaknesses(password);
    
    // Update UI
    updateCharsetIndicators(charSets);
    updateResults(password.length, charsetSize, entropy, keyspace);
    updateCrackTimes(crackTimes);
    updateStrengthMeter(entropy);
    updateWarnings(warnings);
    
    // Show results
    resultsSection.style.display = 'block';
}

function detectCharacterSets(password) {
    return {
        lowercase: /[a-z]/.test(password),
        uppercase: /[A-Z]/.test(password),
        digits: /[0-9]/.test(password),
        symbols: /[^a-zA-Z0-9]/.test(password)
    };
}

function calculateCharsetSize(charSets) {
    let size = 0;
    if (charSets.lowercase) size += CHARSET_SIZES.lowercase;
    if (charSets.uppercase) size += CHARSET_SIZES.uppercase;
    if (charSets.digits) size += CHARSET_SIZES.digits;
    if (charSets.symbols) size += CHARSET_SIZES.symbols;
    return size;
}

function calculateEntropy(length, charsetSize) {
    if (charsetSize === 0) return 0;
    return length * Math.log2(charsetSize);
}

function calculateCrackTimes(averageGuesses) {
    return {
        online: averageGuesses / ATTACKER_SPEEDS.online,
        gpu: averageGuesses / ATTACKER_SPEEDS.gpu,
        cluster: averageGuesses / ATTACKER_SPEEDS.cluster,
        asic: averageGuesses / ATTACKER_SPEEDS.asic
    };
}

function formatTime(seconds) {
    if (!isFinite(seconds) || seconds < 0) {
        return 'Incalculable';
    }
    
    if (seconds < 0.001) {
        return 'Instant';
    }
    
    if (seconds < 1) {
        return `${(seconds * 1000).toFixed(2)} milliseconds`;
    }
    
    if (seconds < 60) {
        return `${seconds.toFixed(2)} seconds`;
    }
    
    const minutes = seconds / 60;
    if (minutes < 60) {
        return `${minutes.toFixed(2)} minutes`;
    }
    
    const hours = minutes / 60;
    if (hours < 24) {
        return `${hours.toFixed(2)} hours`;
    }
    
    const days = hours / 24;
    if (days < 365) {
        return `${days.toFixed(2)} days`;
    }
    
    const years = days / 365.25;
    if (years < 1000) {
        return `${years.toFixed(2)} years`;
    }
    
    if (years < 1000000) {
        return `${(years / 1000).toFixed(2)} thousand years`;
    }
    
    if (years < 1000000000) {
        return `${(years / 1000000).toFixed(2)} million years`;
    }
    
    if (years < 1000000000000) {
        return `${(years / 1000000000).toFixed(2)} billion years`;
    }
    
    return `${(years / 1000000000000).toFixed(2)} trillion years`;
}

function detectWeaknesses(password) {
    const warnings = [];
    
    // Check length
    if (password.length < 8) {
        warnings.push('Password is too short (minimum 8 characters recommended)');
    }
    
    // Check for repeated characters
    if (/(.)\1{2,}/.test(password)) {
        warnings.push('Contains repeated characters (e.g., "aaa", "111")');
    }
    
    // Check for sequential patterns
    if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(password)) {
        warnings.push('Contains sequential letters (e.g., "abc", "xyz")');
    }
    
    if (/012|123|234|345|456|567|678|789/.test(password)) {
        warnings.push('Contains sequential numbers (e.g., "123", "456")');
    }
    
    // Check for keyboard patterns
    if (/qwerty|asdf|zxcv|qaz|wsx|edc/i.test(password)) {
        warnings.push('Contains keyboard patterns (e.g., "qwerty", "asdf")');
    }
    
    // Check for common passwords (partial list)
    const commonPasswords = [
        'password', 'Password', 'PASSWORD',
        '123456', '12345678', '1234567890',
        'qwerty', 'abc123', 'password123',
        'admin', 'letmein', 'welcome',
        'monkey', 'dragon', 'master',
        'sunshine', 'princess', 'football'
    ];
    
    const lowerPassword = password.toLowerCase();
    for (const common of commonPasswords) {
        if (lowerPassword.includes(common.toLowerCase())) {
            warnings.push('Contains a common password or pattern');
            break;
        }
    }
    
    return warnings;
}

function updateCharsetIndicators(charSets) {
    updateCheckbox(lowercaseCheck, charSets.lowercase);
    updateCheckbox(uppercaseCheck, charSets.uppercase);
    updateCheckbox(digitsCheck, charSets.digits);
    updateCheckbox(symbolsCheck, charSets.symbols);
}

function updateCheckbox(element, isChecked) {
    const checkbox = element.querySelector('.checkbox');
    checkbox.textContent = isChecked ? '☑' : '☐';
    element.style.opacity = isChecked ? '1' : '0.5';
}

function updateResults(length, charsetSize, entropy, keyspace) {
    lengthDisplay.textContent = length;
    charsetSizeDisplay.textContent = charsetSize;
    entropyDisplay.textContent = `${entropy.toFixed(2)} bits`;
    keyspaceDisplay.textContent = `~2^${keyspace.toFixed(1)}`;
}

function updateCrackTimes(times) {
    timeOnline.textContent = formatTime(times.online);
    timeGpu.textContent = formatTime(times.gpu);
    timeCluster.textContent = formatTime(times.cluster);
    timeAsic.textContent = formatTime(times.asic);
}

function updateStrengthMeter(entropy) {
    let strength, color, label;
    
    if (entropy < 28) {
        strength = 20;
        color = '#d32f2f';
        label = 'Very Weak';
    } else if (entropy < 36) {
        strength = 40;
        color = '#f57c00';
        label = 'Weak';
    } else if (entropy < 60) {
        strength = 60;
        color = '#fbc02d';
        label = 'Fair';
    } else if (entropy < 80) {
        strength = 80;
        color = '#689f38';
        label = 'Good';
    } else if (entropy < 100) {
        strength = 90;
        color = '#388e3c';
        label = 'Strong';
    } else {
        strength = 100;
        color = '#1976d2';
        label = 'Very Strong';
    }
    
    strengthBar.style.width = `${strength}%`;
    strengthBar.style.backgroundColor = color;
    strengthLabel.textContent = `Strength: ${label} (${entropy.toFixed(2)} bits)`;
    strengthLabel.style.color = color;
}

function updateWarnings(warnings) {
    if (warnings.length === 0) {
        warningsSection.style.display = 'none';
        return;
    }
    
    warningsSection.style.display = 'block';
    warningsList.innerHTML = '';
    
    warnings.forEach(warning => {
        const li = document.createElement('li');
        li.textContent = warning;
        warningsList.appendChild(li);
    });
}

function resetDisplay() {
    resultsSection.style.display = 'none';
    warningsSection.style.display = 'none';
    strengthBar.style.width = '0%';
    strengthLabel.textContent = 'Enter a password to analyze';
    strengthLabel.style.color = '#666';
    
    // Reset checkboxes
    updateCheckbox(lowercaseCheck, false);
    updateCheckbox(uppercaseCheck, false);
    updateCheckbox(digitsCheck, false);
    updateCheckbox(symbolsCheck, false);
}

// Initialize
resetDisplay();
