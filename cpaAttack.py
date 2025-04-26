import requests
import time

USERNAME = "testuser"
PASSWORD = "testpass"
SERVER_URL = "http://192.168.254.28:5000"

M0 = bytes([0x00] * 32)
M1 = bytes([0xFF] * 32)

def encrypt(message_hex):
    payload = {
        "username": USERNAME,
        "password": PASSWORD,
        "message": message_hex
    }
    response = requests.post(SERVER_URL + "/encrypt", json=payload)
    response.raise_for_status()
    return response.json()

def challenge(m0_hex, m1_hex):
    payload = {
        "username": USERNAME,
        "password": PASSWORD,
        "m0": m0_hex,
        "m1": m1_hex
    }
    response = requests.post(SERVER_URL + "/challenge", json=payload)
    response.raise_for_status()
    return response.json()

def guess(challenge_id, b_prime):
    payload = {
        "username": USERNAME,
        "password": PASSWORD,
        "challenge_id": challenge_id,
        "b_prime": b_prime
    }
    response = requests.post(SERVER_URL + "/guess", json=payload)
    response.raise_for_status()
    return response.json()

def recover_pads():
    pad_dict = {}
    print("\n-- TASK 1: Recovering Pads for All r values --\n")

    while len(pad_dict) < 32:
        enc = encrypt(M0.hex())
        r = enc["r"]
        c2 = bytes.fromhex(enc["c2"])
        if r not in pad_dict:
            pad_dict[r] = c2
            print(f"[Pad Recovery] r = {r:2d} pad collected.")
        time.sleep(0.05)

    print("\nAll 32 pads recovered.\n")
    return pad_dict

def main():
    pad_dict = recover_pads()

    wins = 0
    attempts = 0

    print("\n--Task 2: Starting CPA Attack Challenges--\n")

    while wins < 100:
        print(f"[Challenge #{wins+1}] Requesting challenge...")

        chal = challenge(M0.hex(), M1.hex())
        cid = chal["challenge_id"]
        r = chal["r"]
        c2 = bytes.fromhex(chal["c2"])

        pad = pad_dict[r]
        recovered_m = bytes(a ^ b for a, b in zip(pad, c2))

        if recovered_m == M0:
            b_prime = 0
        elif recovered_m == M1:
            b_prime = 1
        else:
            print("Decryption failed, random guess.")
            b_prime = 0

        res = guess(cid, b_prime)
        if res["result"]:
            wins += 1
            print(f"[Challenge #{wins}] Correct guess (Score: {wins}/{attempts+1})\n")
        else:
            print(f"[Challenge #{wins+1}] Wrong guess (Score: {wins}/{attempts+1})\n")
        attempts += 1

    print("\nFinished. 100 correct guesses achieved.\n")

if __name__ == "__main__":
    main()