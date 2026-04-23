# syckmd

A shell-preserving terminal wrapper with inline ghost completion for Windows shells, both Command Prompt and PowerShell.

https://github.com/user-attachments/assets/35a5f8c7-44f3-4fda-917f-926528324b47

## Usage

- `Tab` accepts full suggestion.
- `Ctrl+Tab` or `Ctrl+Right` accepts one word from suggestion.
- `Up` and `Down` navigate command history and suggestions.
- CMD and PowerShell histories and commands are loaded separately.

## Run

1. Build: `cargo build`
2. Start: `cargo run` or `syckmd`
3. Exit: `syckmd --exit`

## Configuration

Configuration can be done via environment variables.

- `SYCKMD_MAX_SUGGESTIONS` (10): Maximum number of suggestions to display.

## Requirements

- Windows 10 or later.
- Rust toolchain for building from source.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contact

xsysctl@proton.me i guess
