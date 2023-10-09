## authWarden
> Secure and manage your TOTPs seamlessly

---

`authWarden` is a powerful command-line utility designed to manage and generate Time-based One-Time Passwords (TOTPs) for various services. With strong cryptographic foundations leveraging the OpenSSL library, along with the OATH library for OTP generation, it's a robust choice for your authentication needs.

---

## Features

- Secure Storage - Keep your service-specific keys encrypted.
- Instant OTP Generation - Generate TOTPs for any registered service at the snap of a finger.
- Reliable Backups - Never lose your data with the backup feature.
- CLI Interface - Perfect for automation and advanced users.

---

## Installation

1. Ensure OpenSSL and OATH libraries are in place.
2. Clone it: `git clone https://github.com/ifHoncho/authWarden.git`
3. Dive in: `cd authWarden`
4. Compile: `gcc -o authWarden main.c -lssl -lcrypto -loath`
5. Start using: `./authWarden`

---

## Usage

- **Interactive Mode:** Simply `./authWarden` and let the prompts guide you.
- **Command-Line Mode:** Direct commands like `./authWarden add <service> <key> <password>` for streamlined operations.

---

## To-Do

- Input Enhancements - Better input methods for varied characters.
- Scalability - Efficient memory management for bulky services.
- Error Handling - Comprehensive management of file operations.
- Customization - Allow user-defined PBKDF2 iterations.
- Backup Handling - Overwrite confirmations for existing backups.

---

## Contribution

Your contributions enrich the community! Fork, modify, and raise a pull request.

---

## License

Under the GNU General Public License v3.0. Dive into the `LICENSE` file for detailed terms.

