# PXuuid: Dynamic & Untraceable Identity Generator (Python Extended UUID System)

### *Ready for True Anonymity? Because with PXuuid, Leaving a Trace is Impossible.*

-----

### Overview

In today's digital world, **static identities** and **traceability** are among the biggest obstacles to privacy. Are we condemned to a future where every click, connection, or interaction leaves the same persistent trail? **PXuuid** steps in at precisely this point\!

PXuuid is a groundbreaking, open-source Python solution that leverages your device's **instantaneous, dynamic, and utterly unpredictable physical and digital state** (CPU load, memory usage, disk & network I/O, high-precision timestamps, and more\!) to create a completely **brand-new and unique identity** every single time.

Even with the underlying algorithm's source code fully open, the generated identities remain **non-reproducible** and **unpredictable**. Why? Because these identities are forged from bits dancing in the **unforeseeable universe** of your computer's current state\!

-----

### Why PXuuid? Differentiating Features

  * **⚡️ True Untraceability: Digital Vaporization.**
    Traditional IDs cling to you like a shadow. PXuuid shatters that link. Every connection, every session, every interaction yields a new identity. The "you" from moments ago is cryptographically disconnected from the "you" now. Leaving a trace? **Mission: Impossible.**
  * **🛡️ Unbreakable Security (Practically\!).**
    Your identities are not just unique; they're **fortified with military-grade cryptography**. Powered by **Argon2 (KDF)** and **SHA-256**, PXuuid employs a multi-layered defense. Dynamic system data meets freshly generated, unique salts for each chunk, then undergoes computationally intensive KDF processing. The result? IDs that are **practically invulnerable to brute-force and sophisticated attacks.**
  * **🌌 "Naclception" Layer: Depths of the Cryptographic Dream.**
    Want to infuse your own essence of unpredictability? Optionally, contribute a random word or phrase. This "cryptographic layering" doesn't just add a sprinkle; it **dynamically splits your input into random chunks, salts each one individually, and strengthens it.** It elevates your security to a dreamlike dimension.
  * **☁️ VM Compatible: Anonymity in the Cloud.**
    Running on virtual servers? No problem. PXuuid is specifically **optimized for the constraints of virtual machine environments**, ensuring reliable and dynamic identity generation even without direct physical hardware access. Your privacy isn't limited by your infrastructure.
  * **👁️ Open-Source Transparency: See the Magic, Verify the Security.**
    Our entire codebase is open. We hide nothing. Security experts and developers are invited to independently examine the algorithm's workings and verify its security. **Because true security thrives in the light.**

-----

### How It Works (The Heart of the Technology)

PXuuid's power stems from a meticulously crafted process based on robust cryptographic principles:

1.  **Dynamic Entropy Harvesting:** Collects diverse, constantly changing system metrics: CPU load, memory usage, disk/network I/O stats, high-precision timestamps, running process count, and more. This data forms the random foundation of the identity.
2.  **Chunking & Salting:** Each collected dynamic data point (e.g., "CPU load," "network traffic") is treated as a separate chunk. A **fresh and cryptographically secure, random salt** is added to each chunk at that precise moment.
3.  **Argon2 KDF Strengthening:** Each salted chunk is passed through **Argon2**, a memory- and time-hardened Key Derivation Function. This maximizes entropy, drastically boosts unpredictability, and imposes a substantial computational barrier against brute-force attacks.
4.  **"Naclception" (Optional):** If the user provides a random phrase, it's dynamically split into random sub-chunks, each sub-chunk is individually salted, and then processed again with Argon2 KDF. This contributes a unique layer of randomness to the identity.
5.  **Final Hashing:** All processed system data chunks and the processed user input (if any) are combined. Finally, this combined data block is passed through the **SHA-256** cryptographic hash function, generating the 256-bit final identity.
6.  **User-Friendly Format:** The final identity is presented in an `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` format, in uppercase, for easier readability and copy-pasting.

-----

### Installation & Usage

1.  **Requirements:**

      * Python 3.x
      * `psutil` library
      * `argon2-cffi` library

    To install, run in your terminal:

    ```bash
    pip install psutil argon2-cffi
    ```

2.  **Cloning:**
    Clone the project from GitHub:

    ```bash
    git clone https://github.com/Murqin/PXuuid.git
    cd PXuuid
    ```

3.  **Running:**

    ```bash
    python PXuuid.py
    ```

    The program will ask how many IDs you'd like to generate and optionally for a word/phrase to contribute.

-----

### Contributing

PXuuid believes in the power of the open-source community. We welcome your contributions to enhance security, optimize performance, or add new features\! For bug reports, feature suggestions, or code contributions, please review our [Contributing Guidelines](https://github.com/Murqin/PXuuid/blob/main/CONTRIBUTING.md) or directly open a `Pull Request`.

-----

### License

This project is licensed under the [MIT License](https://github.com/Murqin/PXuuid/blob/main/LICENSE). See the `LICENSE` file for more details.

-----

### Contact

Got questions or feedback? Feel free to reach out via the [GitHub Issues](https://github.com/Murqin/PXuuid/issues) section.

-----
