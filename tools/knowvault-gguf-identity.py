"""Read-only GGUF v2/v3 artifact and embedded-tokenizer identity.

Tokenizer hash: concatenated original key/type/value records whose keys begin
with tokenizer., in file order. The complete file hash also binds that order.
Spec: https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
"""
import hashlib
import json
import struct
import sys


def identify(path):
    with open(path, "rb") as stream:
        def read(size):
            if size < 0 or size > 256 * 1024 * 1024:
                raise ValueError("GGUF metadata size outside qualification limit")
            value = stream.read(size)
            if len(value) != size:
                raise ValueError("Truncated GGUF")
            return value

        def number(fmt):
            return struct.unpack("<" + fmt, read(struct.calcsize("<" + fmt)))[0]

        def string():
            return read(number("Q")).decode("utf-8")

        def value(kind, depth=0):
            if depth > 3:
                raise ValueError("Nested GGUF metadata exceeds limit")
            scalar = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}
            if kind in scalar:
                return number(scalar[kind])
            if kind == 8:
                return string()
            if kind == 9:
                subtype, count = number("I"), number("Q")
                if count > 2_000_000:
                    raise ValueError("GGUF array exceeds qualification limit")
                for _ in range(count):
                    value(subtype, depth + 1)
                return {"elements": count, "type": subtype}
            raise ValueError("Unknown GGUF metadata type")

        if read(4) != b"GGUF":
            raise ValueError("Not little-endian GGUF")
        version = number("I")
        if version not in (2, 3):
            raise ValueError("Unsupported GGUF version")
        tensors, entries = number("Q"), number("Q")
        if entries > 100_000:
            raise ValueError("GGUF metadata count exceeds qualification limit")
        tokenizer = hashlib.sha256()
        keys, metadata = [], {}
        seen = set()
        for _ in range(entries):
            start = stream.tell()
            key = string()
            if key in seen:
                raise ValueError("Duplicate GGUF key")
            seen.add(key)
            parsed = value(number("I"))
            end = stream.tell()
            if key.startswith("tokenizer."):
                stream.seek(start)
                tokenizer.update(read(end - start))
                keys.append(key)
            if key in ("general.architecture", "general.name", "bert.pooling_type", "bert.embedding_length", "bert.context_length"):
                metadata[key] = parsed
        if not keys:
            raise ValueError("No embedded tokenizer identity")
        stream.seek(0)
        artifact = hashlib.file_digest(stream, "sha256")
        return {"artifact_hash": "sha256:" + artifact.hexdigest(), "tokenizer_hash": "sha256:" + tokenizer.hexdigest(),
                "tokenizer_hash_method": "GGUF raw tokenizer.* key/type/value records in file order", "tokenizer_keys": keys,
                "gguf_version": version, "tensor_count": tensors, "metadata": metadata}


if __name__ == "__main__":
    print(json.dumps(identify(sys.argv[1]), indent=2))
