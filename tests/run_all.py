#!/usr/bin/env python3
import sys
import os
import subprocess
import shutil
import tempfile

def find_executable():
    candidates = [
        os.path.join(".", "lab02.exe"),
        os.path.join(".", "rsatool.exe"),
        os.path.join(".", "build_windows_gcc", "lab02.exe"),
        os.path.join(".", "build_windows_gcc", "rsatool.exe"),
        os.path.join(".", "build", "lab02.exe"),
        os.path.join(".", "build", "rsatool.exe"),
        os.path.join(".", "lab02"),
        os.path.join(".", "rsatool")
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    return None

def main():
    exe = find_executable()
    if not exe:
        print("Error: Could not locate lab02 or rsatool executable. Please build the project first.")
        return 1

    print("============================================================")
    print("      LAB 3 ACCEPTANCE TEST SUITE (A-T1 through E-T9)       ")
    print(f"Target Binary: {exe}")
    print("============================================================\n")

    test_dir = tempfile.mkdtemp(prefix="lab3_tests_")
    passed = 0
    failed = 0

    def run_cmd(args, expected_exit=0, desc="", check_stdout=None):
        nonlocal passed, failed
        cmd = [exe] + args
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
            exit_ok = (res.returncode == expected_exit)
            content_ok = True
            if check_stdout:
                if callable(check_stdout):
                    content_ok = check_stdout(res.stdout)
                else:
                    content_ok = (check_stdout in res.stdout)

            if exit_ok and content_ok:
                print(f"  [PASS] {desc}")
                passed += 1
                return True, res.stdout, res.stderr
            else:
                print(f"  [FAIL] {desc} (expected exit {expected_exit}, got {res.returncode})")
                if res.stderr:
                    print(f"         stderr: {res.stderr.strip()[:100]}")
                if res.stdout and not content_ok:
                    print(f"         stdout: {res.stdout.strip()[:100]}")
                failed += 1
                return False, res.stdout, res.stderr
        except Exception as e:
            print(f"  [FAIL] {desc} (exception: {e})")
            failed += 1
            return False, "", str(e)

    try:
        # Task A
        print("[Task A Tests]")
        run_cmd(["mod-exp", "7", "13", "33"], 0, "A-T1: mod-exp 7 13 33 == 13", "13")
        run_cmd(["gcd", "252", "105"], 0, "A-T2: gcd 252 105 == 21", "21")
        run_cmd(["mod-inverse", "7", "33"], 0, "A-T3: mod-inverse 7 33 == 19", "19")
        run_cmd(["mod-inverse", "6", "33"], 4, "A-T4: mod-inverse 6 33 exits with 4 (no inverse)", "no inverse")
        run_cmd(["mod-sub", "3", "5", "7"], 0, "A-T5: mod-sub 3 5 7 == 5", "5")
        run_cmd(["mod-add", "18446744073709551615", "1", "18446744073709551629"], 0, "A-T6: mod-add 64-bit overflow test", "18446744073709551616")
        run_cmd(["mod-exp", "123456789012345678901234567890", "65537", "170141183460469231731687303715884105727"], 0, "A-T7: Large mod-exp test vector", "43089841487593468092862748681566865937")
        run_cmd(["mod-inverse", "65537", "170141183460469231731687303715884105727"], 0, "A-T8: Large mod-inverse test vector", "5192217631581220737344928932233215")
        run_cmd(["mod-add", "1", "2", "0"], 1, "A-T9a: Rejects m = 0")
        run_cmd(["mod-exp", "-3", "2", "5"], 1, "A-T9b: Rejects negative integer")
        run_cmd(["gcd", "12a", "4"], 1, "A-T9c: Rejects non-digits")
        run_cmd(["gcd", "", "4"], 1, "A-T9d: Rejects empty string")

        # Task B
        print("\n[Task B Tests]")
        run_cmd(["rsa-params", "--bits", "512"], 0, "B-T1: rsa-params 512 bits all checks pass", "PASS")
        keys_dir = os.path.join(test_dir, "keys")
        run_cmd(["keygen", "--bits", "3072", "--out-dir", keys_dir, "--force"], 0, "B-T2: keygen generates 4 key files")

        priv_pem = os.path.join(keys_dir, "private.pem")
        priv_der = os.path.join(keys_dir, "private.der")
        pub_pem = os.path.join(keys_dir, "public.pem")
        pub_der = os.path.join(keys_dir, "public.der")

        run_cmd(["key-check", "--priv", priv_pem, "--pub", pub_pem], 0, "B-T3a: key-check PEM/PEM -> MATCH", "MATCH")
        run_cmd(["key-check", "--priv", priv_der, "--pub", pub_der], 0, "B-T3b: key-check DER/DER -> MATCH", "MATCH")
        run_cmd(["key-check", "--priv", priv_pem, "--pub", pub_der], 0, "B-T3c: key-check PEM/DER -> MATCH", "MATCH")
        run_cmd(["key-check", "--priv", priv_der, "--pub", pub_pem], 0, "B-T3d: key-check DER/PEM -> MATCH", "MATCH")

        keys2_dir = os.path.join(test_dir, "keys2")
        run_cmd(["keygen", "--bits", "2048", "--out-dir", keys2_dir, "--force"], 0, "Generate second keypair")
        priv2_pem = os.path.join(keys2_dir, "private.pem")
        run_cmd(["key-check", "--priv", priv2_pem, "--pub", pub_pem], 4, "B-T4: key-check with mismatched keys -> MISMATCH (exit 4)", "MISMATCH")

        conv_der = os.path.join(test_dir, "conv.der")
        conv_pem = os.path.join(test_dir, "conv.pem")
        run_cmd(["key-convert", "--type", "public", "--in", pub_pem, "--out", conv_der, "--outform", "DER", "--force"], 0, "B-T5a: Convert PEM to DER")
        run_cmd(["key-convert", "--type", "public", "--in", conv_der, "--out", conv_pem, "--outform", "PEM", "--force"], 0, "B-T5b: Convert DER back to PEM")
        run_cmd(["key-info", "--pub", pub_pem], 0, "B-T6: key-info reads modulus and Key ID", "Key ID")

        # Task C
        print("\n[Task C Tests]")
        run_cmd(["os2ip", "--hex", "000001"], 0, "C-T1: os2ip 000001 == 1", "1")
        run_cmd(["i2osp", "--int", "1", "--len", "1"], 0, "C-T2: i2osp 1 len 1 == 01", "01")
        run_cmd(["os2ip", "--hex", "0100"], 0, "C-T3: os2ip 0100 == 256", "256")
        run_cmd(["i2osp", "--int", "256", "--len", "1"], 1, "C-T4: i2osp 256 len 1 fails (integer too large)")
        run_cmd(["os2ip", "--hex", "00ff00"], 0, "C-T5: os2ip 00ff00 == 65280", "65280")
        run_cmd(["os2ip", "--hex", ""], 0, "C-T6: os2ip empty == 0", "0")
        run_cmd(["raw-rsa", "--bits", "512"], 0, "C-T10: raw-rsa runs determinism and malleability checks", "PASS")
        run_cmd(["oaep-demo", "--pub", pub_pem, "--priv", priv_pem], 0, "C-T11: oaep-demo verifies randomized padding", "PASS")

        # Task D
        print("\n[Task D Tests]")
        sample_file = os.path.join(test_dir, "sample.txt")
        open(sample_file, "w").write("Hello NT219 Cryptography Laboratory! RSA-OAEP + AES-256-GCM")
        pkg_d = os.path.join(test_dir, "sample.l2pk")
        dec_d = os.path.join(test_dir, "decrypted.txt")

        run_cmd(["encrypt", "--pub", pub_pem, "--in", sample_file, "--out", pkg_d, "--force"], 0, "D-T1a: Encrypt file with RSA-OAEP")
        run_cmd(["decrypt", "--priv", priv_pem, "--in", pkg_d, "--out", dec_d, "--force"], 0, "D-T1b: Decrypt file with RSA-OAEP")

        dec_content = open(dec_d, "r").read()
        if dec_content == open(sample_file, "r").read():
            print("  [PASS] D-T1c: Decrypted plaintext matches original byte-for-byte")
            passed += 1
        else:
            print("  [FAIL] D-T1c: Decrypted content mismatch")
            failed += 1

        # D-T3: Encrypt twice produces different packages
        pkg_d2 = os.path.join(test_dir, "sample2.l2pk")
        run_cmd(["encrypt", "--pub", pub_pem, "--in", sample_file, "--out", pkg_d2, "--force"], 0, "D-T3: Encrypt twice")
        if open(pkg_d, "rb").read() != open(pkg_d2, "rb").read():
            print("  [PASS] D-T3: Two package encryptions differ (fresh K, N)")
            passed += 1
        else:
            print("  [FAIL] D-T3: Packages identical")
            failed += 1

        # Tamper tests using tests/tamper.py
        tamper_py = os.path.abspath(os.path.join(os.path.dirname(__file__), "tamper.py"))
        tampered_pkg = os.path.join(test_dir, "tampered.l2pk")

        # D-T4: Flip ciphertext byte
        k_val = 384 # 3072 bits / 8
        ct_offset = 30 + k_val
        subprocess.run([sys.executable, tamper_py, pkg_d, tampered_pkg, "flip", str(ct_offset)], check=True)
        run_cmd(["decrypt", "--priv", priv_pem, "--in", tampered_pkg, "--out", os.path.join(test_dir, "bad.txt"), "--force"], 4, "D-T4: Flip ciphertext bit -> exit 4")

        # D-T5: Flip tag byte
        subprocess.run([sys.executable, tamper_py, pkg_d, tampered_pkg, "flip", "-1"], check=True)
        run_cmd(["decrypt", "--priv", priv_pem, "--in", tampered_pkg, "--out", os.path.join(test_dir, "bad.txt"), "--force"], 4, "D-T5: Flip tag bit -> exit 4")

        # D-T6: Flip nonce bit
        subprocess.run([sys.executable, tamper_py, pkg_d, tampered_pkg, "flip", str(10 + k_val)], check=True)
        run_cmd(["decrypt", "--priv", priv_pem, "--in", tampered_pkg, "--out", os.path.join(test_dir, "bad.txt"), "--force"], 4, "D-T6: Flip nonce bit -> exit 4")

        # D-T7: Tamper magic or reserved bytes -> exit 3
        subprocess.run([sys.executable, tamper_py, pkg_d, tampered_pkg, "setbytes", "6", "0001"], check=True)
        run_cmd(["decrypt", "--priv", priv_pem, "--in", tampered_pkg, "--out", os.path.join(test_dir, "bad.txt"), "--force"], 3, "D-T7: Non-zero reserved bytes -> exit 3")

        # D-T8: Truncate 1 byte -> exit 3
        subprocess.run([sys.executable, tamper_py, pkg_d, tampered_pkg, "truncate", "1"], check=True)
        run_cmd(["decrypt", "--priv", priv_pem, "--in", tampered_pkg, "--out", os.path.join(test_dir, "bad.txt"), "--force"], 3, "D-T8: Truncated package -> exit 3")

        # D-T9: Decrypt with wrong private key -> exit 4
        keys3_dir = os.path.join(test_dir, "keys3")
        run_cmd(["keygen", "--bits", "3072", "--out-dir", keys3_dir, "--force"], 0, "Generate third 3072-bit keypair")
        priv3_pem = os.path.join(keys3_dir, "private.pem")
        run_cmd(["decrypt", "--priv", priv3_pem, "--in", pkg_d, "--out", os.path.join(test_dir, "bad.txt"), "--force"], 4, "D-T9: Wrong private key -> exit 4 (decryption failed)")

        # Task E
        print("\n[Task E Tests]")
        run_cmd(["kem-selftest", "--pub", pub_pem, "--priv", priv_pem], 0, "E-T1..4: kem-selftest runs E-T1 through E-T4", "PASS")

        pkg_e = os.path.join(test_dir, "kem_sample.l2pk")
        dec_e = os.path.join(test_dir, "kem_decrypted.txt")
        run_cmd(["kem-encrypt", "--pub", pub_pem, "--in", sample_file, "--out", pkg_e, "--force"], 0, "E-T5a: kem-encrypt creates Mode 0x02 package")
        run_cmd(["kem-decrypt", "--priv", priv_pem, "--in", pkg_e, "--out", dec_e, "--force"], 0, "E-T5b: kem-decrypt extracts plaintext")

        if open(dec_e, "r").read() == open(sample_file, "r").read():
            print("  [PASS] E-T5c: KEM Decrypted plaintext matches original byte-for-byte")
            passed += 1
        else:
            print("  [FAIL] E-T5c: KEM decrypted content mismatch")
            failed += 1

        # E-T7: One bit flipped in kem_ct -> exit 4
        subprocess.run([sys.executable, tamper_py, pkg_e, tampered_pkg, "flip", "50"], check=True)
        run_cmd(["kem-decrypt", "--priv", priv_pem, "--in", tampered_pkg, "--out", os.path.join(test_dir, "bad.txt"), "--force"], 4, "E-T7: Flipped bit in kem_ct -> decaps OK, GCM fails (exit 4)")

        # E-T9: Package mode 0x01 given to kem-decrypt -> exit 3
        run_cmd(["kem-decrypt", "--priv", priv_pem, "--in", pkg_d, "--out", os.path.join(test_dir, "bad.txt"), "--force"], 3, "E-T9: Mode 0x01 package given to kem-decrypt strictly rejected (exit 3)")

    finally:
        shutil.rmtree(test_dir, ignore_errors=True)

    print("\n============================================================")
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("============================================================")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
