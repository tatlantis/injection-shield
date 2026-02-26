import nacl.signing
import nacl.encoding
import json
from datetime import datetime


class TrustedIdentity:
    """Represents a trusted identity that can sign commands"""

    def __init__(self, name: str):
        self.name = name
        self.signing_key = nacl.signing.SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

    def sign_command(self, command: str, metadata: dict = None) -> dict:
        if metadata is None:
            metadata = {}
        metadata['timestamp'] = datetime.utcnow().isoformat()
        metadata['signer'] = self.name

        payload = {'command': command, 'metadata': metadata}
        message = json.dumps(payload, sort_keys=True).encode('utf-8')
        signed = self.signing_key.sign(message)

        return {
            'command': command,
            'metadata': metadata,
            'signature': signed.signature.hex(),
            'verify_key': self.verify_key.encode(
                encoder=nacl.encoding.HexEncoder
            ).decode('utf-8')
        }


def verify_signature(signed_command: dict) -> tuple:
    try:
        verify_key = nacl.signing.VerifyKey(
            signed_command['verify_key'],
            encoder=nacl.encoding.HexEncoder
        )
        payload = {
            'command': signed_command['command'],
            'metadata': signed_command['metadata']
        }
        message = json.dumps(payload, sort_keys=True).encode('utf-8')
        signature = bytes.fromhex(signed_command['signature'])
        verify_key.verify(message, signature)
        return (True, "Signature valid")
    except Exception as e:
        return (False, f"Signature invalid: {str(e)}")


if __name__ == "__main__":
    print("=== InjectionShield - Core Cryptographic Layer ===\n")

    # [1] Create a trusted identity and sign a command
    fred = TrustedIdentity("fred")
    signed = fred.sign_command("execute: analyze_document.py")
    print("[1] Signed command:", json.dumps(signed, indent=2))

    # [2] Verify the legitimate command
    is_valid, message = verify_signature(signed)
    print(f"\n[2] Verification: {is_valid} — {message}")

    # [3] Simulate injection attack: tamper with the command
    signed['command'] = "execute: malicious_script.py"
    is_valid, message = verify_signature(signed)
    print(f"\n[3] Injection attempt detected: {is_valid} — {message}")

    print("\nCore layer working. Injection cannot execute without a valid signature.")
