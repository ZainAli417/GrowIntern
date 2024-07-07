#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Jul  7 09:28:52 2024

@author: root
"""

def calculate_password_strength(password):
    length = len(password)
    special_characters = "!@#$%^&*()-+"
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in special_characters for char in password)

    strength = 0
    if length >= 8:
        strength += 1
    if length >= 12:
        strength += 1
    if has_upper:
        strength += 1
    if has_lower:
        strength += 1
    if has_digit:
        strength += 1
    if has_special:
        strength += 1

    if strength <= 2:
        return 'Weak', 20 * strength
    elif strength == 3:
        return 'Medium', 40 * strength
    elif strength == 4:
        return 'Strong', 20 * strength
    else:
        return 'Extreme', 20 * strength
