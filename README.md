# defaulty-nmap

An Nmap NSE (Nmap Scripting Engine) script that queries the [Defaulty API](https://defaulty.io) for default credentials based on detected services.
You can also use our [REST API](https://defaulty.io/docs).

## Description

This script sends service names and versions detected by Nmap to the [Defaulty API](https://defaulty.io) to retrieve potential default credentials. It requires a valid API token for full functionality.

## Prerequisites

Before you can use this script, you need to have the following:

1. Nmap (https://nmap.org/) with NSE (Nmap Scripting Engine)
2. The [`json` module from rxi](https://github.com/rxi/json.lua) should be available in the Nmap Scripting Engine library (`nselib`)

## Installation

1. **Install Nmap:**
    - For Windows: Download and install from https://nmap.org/download.html
    - For macOS: `brew install nmap`
    - For Linux: `sudo apt-get install nmap` (Ubuntu/Debian) or `sudo yum install nmap` (CentOS/RHEL)

2. **Install the script:**
    - Copy the `defaulty-nmap.nse` file to Nmap's scripts directory:
        - Windows: `C:\Program Files (x86)\Nmap\scripts\`
        - macOS/Linux: `/usr/share/nmap/scripts/`

3. **Update the script database:**
   Run the following command:
   ```bash
   nmap --script-updatedb
   ```

## Usage

To use the script, you need to run Nmap with the `-A` option (for version detection) and specify the `defaulty-nmap` script. You also need to provide your Defaulty API token.

Basic usage:

```bash
nmap -A -p- --script defaulty-nmap --script-args defaulty-nmap.apitoken=your_api_token_here <target>
```

Replace `your_api_token_here` with your actual Defaulty API token.

For more usage examples, please refer to the script's documentation by running:

```bash
nmap --script-help defaulty-nmap
```

## API Token

You need a valid API token from Defaulty to use this script. You can provide the token in two ways:

1. As a script argument: `--script-args defaulty-nmap.apitoken=your_api_token_here`
2. As an environment variable: Set the `DEFAULTY_API_TOKEN` environment variable before running the script.

You can retrieve and revoke your API token in the [Defaulty dashboard](https://defaulty.io/dashboard).

## Important Note

Always use the `-A` option with this script. Without it, the script cannot detect accurate service names and versions, which are crucial for querying the Defaulty API effectively.

## License
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Contributing

Contributions to improve the script are welcome. Please feel free to submit issues or pull requests on the project's GitHub page.

## Disclaimer

This script is for educational and ethical testing purposes only. Always ensure you have permission before scanning any networks or systems you do not own or have explicit permission to test.