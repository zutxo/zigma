#!/usr/bin/env python3
"""
Extract test vectors from Scala sigmastate-interpreter test files.

Parses LanguageSpecificationV5.scala to extract input/output pairs
for conformance testing in the Zig implementation.

Output format: JSON files for each category of operations.
"""

import re
import json
import sys
from pathlib import Path
from typing import Any

SCALA_TEST_FILE = Path("/home/mark/ergotree-research/scala/sigmastate/sc/shared/src/test/scala/sigma/LanguageSpecificationV5.scala")
OUTPUT_DIR = Path(__file__).parent.parent / "tests" / "vectors"


def parse_byte_value(s: str) -> int | None:
    """Parse Scala byte literal like '(-128.toByte)' or '127.toByte'"""
    s = s.strip()
    # Handle parenthesized negative
    m = re.match(r'\((-?\d+)\.toByte\)', s)
    if m:
        return int(m.group(1))
    # Handle simple positive
    m = re.match(r'(-?\d+)\.toByte', s)
    if m:
        return int(m.group(1))
    # Handle Byte.MaxValue / Byte.MinValue
    if s == 'Byte.MaxValue':
        return 127
    if s == 'Byte.MinValue':
        return -128
    return None


def parse_short_value(s: str) -> int | None:
    """Parse Scala short literal"""
    s = s.strip()
    m = re.match(r'\((-?\d+)\.toShort\)', s)
    if m:
        return int(m.group(1))
    m = re.match(r'(-?\d+)\.toShort', s)
    if m:
        return int(m.group(1))
    if s == 'Short.MaxValue':
        return 32767
    if s == 'Short.MinValue':
        return -32768
    return None


def parse_int_value(s: str) -> int | None:
    """Parse Scala int literal"""
    s = s.strip()
    # Try plain integer
    m = re.match(r'^(-?\d+)$', s)
    if m:
        return int(m.group(1))
    # Byte/Short max/min promoted to int
    if s == 'Byte.MaxValue.toInt':
        return 127
    if s == 'Byte.MinValue.toInt':
        return -128
    if s == 'Short.MaxValue.toInt':
        return 32767
    if s == 'Short.MinValue.toInt':
        return -32768
    if s == 'Int.MaxValue':
        return 2147483647
    if s == 'Int.MinValue':
        return -2147483648
    return None


def parse_long_value(s: str) -> int | None:
    """Parse Scala long literal"""
    s = s.strip()
    m = re.match(r'^(-?\d+)L$', s)
    if m:
        return int(m.group(1))
    if s == 'Long.MaxValue':
        return 9223372036854775807
    if s == 'Long.MinValue':
        return -9223372036854775808
    return None


def parse_boolean(s: str) -> bool | None:
    """Parse Scala boolean literal"""
    s = s.strip()
    if s == 'true':
        return True
    if s == 'false':
        return False
    return None


def extract_binxor_cases(content: str) -> list[dict]:
    """Extract BinXor (logical XOR) test cases."""
    cases = []

    # Find the BinXor property block
    match = re.search(
        r'property\("BinXor\(logical XOR\) equivalence"\).*?val cases = Seq\((.*?)\)\s*verifyCases',
        content, re.DOTALL
    )

    if not match:
        return cases

    case_block = match.group(1)

    # Parse each case: (true, true) -> success(false)
    for line in case_block.split('\n'):
        m = re.search(r'\((\w+),\s*(\w+)\)\s*->\s*success\((\w+)\)', line)
        if m:
            a = parse_boolean(m.group(1))
            b = parse_boolean(m.group(2))
            result = parse_boolean(m.group(3))
            if a is not None and b is not None and result is not None:
                cases.append({
                    "input": [a, b],
                    "expected": result
                })

    return cases


def extract_boolean_cases_generic(content: str, property_pattern: str) -> list[dict]:
    """Extract boolean test cases using a generic pattern."""
    cases = []

    match = re.search(
        property_pattern + r'.*?val cases = Seq\((.*?)\)\s*verifyCases',
        content, re.DOTALL
    )

    if not match:
        return cases

    case_block = match.group(1)

    # Try both patterns: success(result) and Expected(Success(result), ...)
    for line in case_block.split('\n'):
        # Pattern 1: (a, b) -> success(result)
        m = re.search(r'\((\w+),\s*(\w+)\)\s*->\s*success\((\w+)\)', line)
        if m:
            a = parse_boolean(m.group(1))
            b = parse_boolean(m.group(2))
            result = parse_boolean(m.group(3))
            if a is not None and b is not None and result is not None:
                cases.append({"input": [a, b], "expected": result})
            continue

        # Pattern 2: (a, b) -> Expected(Success(result), ...)
        m = re.search(r'\((\w+),\s*(\w+)\)\s*->\s*Expected\(Success\((\w+)\)', line)
        if m:
            a = parse_boolean(m.group(1))
            b = parse_boolean(m.group(2))
            result = parse_boolean(m.group(3))
            if a is not None and b is not None and result is not None:
                cases.append({"input": [a, b], "expected": result})

    return cases


def extract_boolean_and_cases(content: str) -> list[dict]:
    """Extract && boolean test cases."""
    return extract_boolean_cases_generic(content, r'property\("&& boolean equivalence"\)')


def extract_boolean_or_cases(content: str) -> list[dict]:
    """Extract || boolean test cases."""
    return extract_boolean_cases_generic(content, r'property\("\|\| boolean equivalence"\)')


def extract_byte_arithmetic_cases(content: str) -> list[dict]:
    """Extract Byte arithmetic test cases (plus, minus, mul, div, mod)."""
    cases = []

    # Find the Byte methods property block with arithmetic
    match = re.search(
        r'val n = ExactIntegral\.ByteIsExactIntegral.*?verifyCases\(\s*\{.*?Seq\((.*?)\)\s*\},',
        content, re.DOTALL
    )

    if not match:
        return cases

    case_block = match.group(1)

    # Parse success cases: ((a, b), success((plus, (minus, (mul, (div, mod))))))
    # Pattern for success case with result tuple
    success_pattern = re.compile(
        r'\(\(([^,]+),\s*([^)]+)\),\s*success\(\(([^,]+),\s*\(([^,]+),\s*\(([^,]+),\s*\(([^,]+),\s*([^)]+)\)\)\)\)\)'
    )

    # Pattern for exception case
    error_pattern = re.compile(
        r'\(\(([^,]+),\s*([^)]+)\),\s*Expected\(new ArithmeticException\("([^"]+)"\)\)'
    )

    for line in case_block.split('\n'):
        # Try success pattern
        m = success_pattern.search(line)
        if m:
            a = parse_byte_value(m.group(1))
            b = parse_byte_value(m.group(2))
            plus = parse_byte_value(m.group(3))
            minus = parse_byte_value(m.group(4))
            mul = parse_byte_value(m.group(5))
            div = parse_byte_value(m.group(6))
            mod = parse_byte_value(m.group(7))

            if all(v is not None for v in [a, b, plus, minus, mul, div, mod]):
                cases.append({
                    "input": [a, b],
                    "expected": {
                        "plus": plus,
                        "minus": minus,
                        "multiply": mul,
                        "divide": div,
                        "modulo": mod
                    }
                })
            continue

        # Try error pattern
        m = error_pattern.search(line)
        if m:
            a = parse_byte_value(m.group(1))
            b = parse_byte_value(m.group(2))
            error = m.group(3)

            if a is not None and b is not None:
                cases.append({
                    "input": [a, b],
                    "expected": {"error": error}
                })

    return cases


def extract_byte_comparison_cases(content: str) -> list[dict]:
    """Extract Byte comparison test cases (LT, GT, NEQ)."""
    cases = []

    # Find Byte LT, GT, NEQ property block
    match = re.search(
        r'property\("Byte LT, GT, NEQ"\).*?val LT_cases.*?Seq\((.*?)\)\s*,',
        content, re.DOTALL
    )

    if match:
        lt_block = match.group(1)
        for line in lt_block.split('\n'):
            m = re.search(r'\(\(([^,]+),\s*([^)]+)\)\s*->\s*(\w+)\)', line)
            if m:
                a = parse_byte_value(m.group(1))
                b = parse_byte_value(m.group(2))
                result_str = m.group(3)
                result = result_str == 'true'
                if a is not None and b is not None:
                    cases.append({
                        "operation": "lt",
                        "input": [a, b],
                        "expected": result
                    })

    return cases


def extract_upcast_cases(content: str) -> list[dict]:
    """Extract upcast test cases (Byte to Short, Int, Long, BigInt)."""
    cases = []

    # Byte to Short upcast
    match = re.search(
        r'existingFeature\(\s*\(x: Byte\) => x\.toShort.*?Seq\((.*?)\)\s*\},',
        content, re.DOTALL
    )

    if match:
        case_block = match.group(1)
        for line in case_block.split('\n'):
            m = re.search(r'\(([^,]+),\s*expected\(([^)]+)\)\)', line)
            if m:
                input_val = parse_byte_value(m.group(1))
                output_val = parse_short_value(m.group(2))
                if input_val is not None and output_val is not None:
                    cases.append({
                        "operation": "byte_to_short",
                        "input": input_val,
                        "expected": output_val
                    })

    return cases


def generate_manual_vectors() -> dict:
    """Generate manually verified test vectors for common operations."""
    return {
        "xor": [
            {"input": [False, False], "expected": False},
            {"input": [False, True], "expected": True},
            {"input": [True, False], "expected": True},
            {"input": [True, True], "expected": False},
        ],
        "and": [
            {"input": [False, False], "expected": False},
            {"input": [False, True], "expected": False},
            {"input": [True, False], "expected": False},
            {"input": [True, True], "expected": True},
        ],
        "or": [
            {"input": [False, False], "expected": False},
            {"input": [False, True], "expected": True},
            {"input": [True, False], "expected": True},
            {"input": [True, True], "expected": True},
        ],
        "not": [
            {"input": False, "expected": True},
            {"input": True, "expected": False},
        ],
        # Byte comparisons
        "byte_lt": [
            {"input": [0, 0], "expected": False},
            {"input": [0, 1], "expected": True},
            {"input": [1, 0], "expected": False},
            {"input": [-1, 0], "expected": True},
            {"input": [0, -1], "expected": False},
            {"input": [-128, 127], "expected": True},
            {"input": [127, -128], "expected": False},
            {"input": [-128, -128], "expected": False},
            {"input": [127, 127], "expected": False},
        ],
        "byte_eq": [
            {"input": [0, 0], "expected": True},
            {"input": [0, 1], "expected": False},
            {"input": [127, 127], "expected": True},
            {"input": [-128, -128], "expected": True},
            {"input": [-1, 255], "expected": False},  # Byte is signed
        ],
        # Int comparisons
        "int_lt": [
            {"input": [0, 0], "expected": False},
            {"input": [0, 1], "expected": True},
            {"input": [-1, 0], "expected": True},
            {"input": [2147483647, -2147483648], "expected": False},
            {"input": [-2147483648, 2147483647], "expected": True},
        ],
        # Long comparisons
        "long_lt": [
            {"input": [0, 0], "expected": False},
            {"input": [0, 1], "expected": True},
            {"input": [9223372036854775807, -9223372036854775808], "expected": False},
        ],
        # Byte upcast
        "byte_to_short": [
            {"input": 0, "expected": 0},
            {"input": 127, "expected": 127},
            {"input": -128, "expected": -128},
            {"input": -1, "expected": -1},
        ],
        "byte_to_int": [
            {"input": 0, "expected": 0},
            {"input": 127, "expected": 127},
            {"input": -128, "expected": -128},
        ],
        "byte_to_long": [
            {"input": 0, "expected": 0},
            {"input": 127, "expected": 127},
            {"input": -128, "expected": -128},
        ],
        # Hash functions (empty input)
        "blake2b256_empty": {
            "input": [],
            "expected": [
                0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2,
                0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99, 0xda, 0xa1,
                0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87,
                0xfa, 0xab, 0x45, 0xcd, 0xf1, 0x2f, 0xe3, 0xa8
            ]
        },
        "sha256_empty": {
            "input": [],
            "expected": [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
            ]
        },
    }


def main():
    """Main entry point."""
    if not SCALA_TEST_FILE.exists():
        print(f"Error: Scala test file not found: {SCALA_TEST_FILE}")
        sys.exit(1)

    print(f"Reading {SCALA_TEST_FILE}...")
    content = SCALA_TEST_FILE.read_text()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Get manual vectors
    manual = generate_manual_vectors()

    # Extract logical operations (combine extracted + manual)
    xor_extracted = extract_binxor_cases(content)
    and_extracted = extract_boolean_and_cases(content)
    or_extracted = extract_boolean_or_cases(content)

    logical_vectors = {
        "category": "logical",
        "description": "Boolean logical operations",
        "operations": {
            "xor": xor_extracted if xor_extracted else manual["xor"],
            "and": and_extracted if and_extracted else manual["and"],
            "or": or_extracted if or_extracted else manual["or"],
            "not": manual["not"]
        }
    }

    logical_path = OUTPUT_DIR / "logical.json"
    with open(logical_path, 'w') as f:
        json.dump(logical_vectors, f, indent=2)
    print(f"Wrote {logical_path}: {sum(len(v) for v in logical_vectors['operations'].values())} cases")

    # Extract byte arithmetic
    byte_arith_cases = extract_byte_arithmetic_cases(content)
    arithmetic_vectors = {
        "category": "arithmetic",
        "description": "Numeric arithmetic operations with overflow checking",
        "byte_operations": byte_arith_cases
    }

    arith_path = OUTPUT_DIR / "arithmetic.json"
    with open(arith_path, 'w') as f:
        json.dump(arithmetic_vectors, f, indent=2)
    print(f"Wrote {arith_path}: {len(byte_arith_cases)} byte arithmetic cases")

    # Comparison operations (use manual vectors as primary source)
    comparison_vectors = {
        "category": "comparison",
        "description": "Numeric comparison operations",
        "byte_lt": manual["byte_lt"],
        "byte_eq": manual["byte_eq"],
        "int_lt": manual["int_lt"],
        "long_lt": manual["long_lt"]
    }

    comp_path = OUTPUT_DIR / "comparison.json"
    with open(comp_path, 'w') as f:
        json.dump(comparison_vectors, f, indent=2)
    comp_count = sum(len(v) for v in [manual["byte_lt"], manual["byte_eq"], manual["int_lt"], manual["long_lt"]])
    print(f"Wrote {comp_path}: {comp_count} comparison cases")

    # Type conversion operations (use manual vectors)
    conversion_vectors = {
        "category": "conversion",
        "description": "Type conversion operations",
        "upcast": {
            "byte_to_short": manual["byte_to_short"],
            "byte_to_int": manual["byte_to_int"],
            "byte_to_long": manual["byte_to_long"]
        }
    }

    conv_path = OUTPUT_DIR / "conversion.json"
    with open(conv_path, 'w') as f:
        json.dump(conversion_vectors, f, indent=2)
    conv_count = sum(len(v) for v in [manual["byte_to_short"], manual["byte_to_int"], manual["byte_to_long"]])
    print(f"Wrote {conv_path}: {conv_count} conversion cases")

    # Crypto operations
    crypto_vectors = {
        "category": "crypto",
        "description": "Cryptographic hash operations",
        "blake2b256": [manual["blake2b256_empty"]],
        "sha256": [manual["sha256_empty"]]
    }

    crypto_path = OUTPUT_DIR / "crypto.json"
    with open(crypto_path, 'w') as f:
        json.dump(crypto_vectors, f, indent=2)
    print(f"Wrote {crypto_path}: 2 crypto hash cases")

    total = (
        sum(len(v) for v in logical_vectors['operations'].values()) +
        len(byte_arith_cases) +
        comp_count +
        conv_count +
        2  # crypto
    )
    print(f"\nTotal: {total} test vectors extracted")


if __name__ == "__main__":
    main()
