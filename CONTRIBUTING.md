# Contributing to synscan

Thank you for considering contributing to `synscan`! Contributions are welcome to improve performance, add features, or refine network protocol support.

## How to Contribute

1. **Fork the Repository**: Create a personal fork on GitHub.
2. **Create a Feature Branch**: `git checkout -b feature/my-new-feature`
3. **Make Your Changes**: Keep code clean, functional, and pythonic.
4. **Test Your Changes**: Verify compilation and CLI execution:
   ```bash
   python3 -m py_compile synscan.py synscan/*.py
   python3 synscan.py --help
   ```
5. **Commit and Push**: Write clear, descriptive commit messages.
6. **Submit a Pull Request**: Provide a brief summary of your changes in the PR description.

## Code Guidelines

- Maintain low memory overhead and high packet throughput.
- Keep standard library dependency footprint minimal (no heavy third-party requirements).
- Test raw socket behavior carefully on POSIX systems (Linux/macOS).

Thank you for helping make `synscan` better!
