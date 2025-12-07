# attackUtility.py
"""
attackUtility.py
----------------
Helpers to simulate attacks on the secure messaging app.

First attack: Dictionary attack against weak passwords.

This is for EDUCATIONAL USE ONLY within the ICS 344 project.
Do NOT use this logic against real systems or real users.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


# This matches the structure in app.py:
# USERS = {
#   "Alice":   {"password": "alice123", ...},
#   "Bob":     {"password": "bob123",   ...},
#   "Charlie": {"password": "charlie123", ...},
#   ...
# }

# Example small dictionary of common weak passwords
COMMON_PASSWORDS: List[str] = [
    "123456",
    "password",
    "123456789",
    "qwerty",
    "abc123",
    "password1",
    "111111",
    "letmein",
    "iloveyou",
    "123123",
    "alice123",   # intentionally includes your demo passwords
    "bob123",
    "charlie123",
]


@dataclass
class DictionaryAttackResult:
    username: str
    success: bool
    guessed_password: Optional[str]
    attempts: int
    tried_passwords: List[str]
    remaining_passwords: int
    note: str


def run_dictionary_attack(
        username: str,
        user_db: Dict[str, Dict],
        wordlist: Optional[List[str]] = None,
        max_attempts: Optional[int] = None,
) -> DictionaryAttackResult:
    """
    Simulate a dictionary attack against the in-memory user_db.

    Parameters
    ----------
    username : str
        Target username to attack (must exist in user_db).
    user_db : dict
        The USERS structure from app.py, or any similar dict
        where user_db[username]["password"] stores the clear-text password.
        (In the real world you would NOT keep clear-text passwords.)
    wordlist : list[str], optional
        List of candidate passwords to try. If None, COMMON_PASSWORDS is used.
    max_attempts : int, optional
        Limit number of guesses (for simulating lockout). If None, try all.

    Returns
    -------
    DictionaryAttackResult
        Contains whether the attack succeeded, how many attempts were used,
        which passwords were tried, and any extra notes.
    """
    if wordlist is None:
        wordlist = COMMON_PASSWORDS

    if username not in user_db:
        return DictionaryAttackResult(
            username=username,
            success=False,
            guessed_password=None,
            attempts=0,
            tried_passwords=[],
            remaining_passwords=len(wordlist),
            note=f"User '{username}' does not exist in user_db.",
        )

    target_password = user_db[username].get("password")
    if target_password is None:
        return DictionaryAttackResult(
            username=username,
            success=False,
            guessed_password=None,
            attempts=0,
            tried_passwords=[],
            remaining_passwords=len(wordlist),
            note=f"User '{username}' has no 'password' field in user_db.",
        )

    tried: List[str] = []
    attempts = 0
    found_password: Optional[str] = None

    for candidate in wordlist:
        tried.append(candidate)
        attempts += 1

        if candidate == target_password:
            found_password = candidate
            break

        if max_attempts is not None and attempts >= max_attempts:
            break

    success = found_password is not None
    remaining = max(0, len(wordlist) - attempts)

    if success:
        note = (
            f"Dictionary attack SUCCESS for user '{username}'. "
            f"Password guessed in {attempts} attempts."
        )
    else:
        if max_attempts is not None and attempts >= max_attempts:
            note = (
                f"Dictionary attack stopped after reaching max_attempts={max_attempts} "
                f"for user '{username}'. Password not found in tested range."
            )
        else:
            note = (
                f"Dictionary attack FAILED for user '{username}'. "
                f"Password not present in provided dictionary."
            )

    return DictionaryAttackResult(
        username=username,
        success=success,
        guessed_password=found_password,
        attempts=attempts,
        tried_passwords=tried,
        remaining_passwords=remaining,
        note=note,
    )


def pretty_print_attack_result(result: DictionaryAttackResult) -> str:
    """
    Return a multi-line human-readable description of the dictionary attack result.
    Useful for printing to console or logs.
    """
    lines = [
        f"[Dictionary Attack Report]",
        f"Target user: {result.username}",
        f"Success: {result.success}",
        f"Attempts used: {result.attempts}",
        f"Remaining passwords in dictionary: {result.remaining_passwords}",
        f"Note: {result.note}",
    ]
    if result.success:
        lines.append(f"Guessed password: '{result.guessed_password}'")
    else:
        lines.append("Guessed password: (none)")
    lines.append(f"Tried passwords (in order): {result.tried_passwords}")
    return "\n".join(lines)
