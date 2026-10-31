![Banner](banner.png)

# crypto-block-mode-analyzer
Analyzes ciphertext for the likely block cipher mode without requiring the key. It reports ECB when block repetition is found, reports CTR only from an optional statistical byte frequency test, and otherwise reports an undetermined outcome: CBC, CFB, and OFB cannot be told apart from each other on ciphertext alone. - Focused on Basic cryptographic operations

## Install
`git clone https://github.com/ShadowStrikeHQ/crypto-block-mode-analyzer`

## Usage
`./crypto-block-mode-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--block_size`: No description provided
- `--threshold`: No description provided
- `--sample_size`: No description provided
- `--enable_ctr_test`: Enable statistical tests for CTR mode, which is time intensive.

## License
Copyright (c) ShadowStrikeHQ
