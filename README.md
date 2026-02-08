# Cloudflare Manager

A simple GUI application to automate common Cloudflare tasks. It allows you to quickly add new domains, set up email routing (catch-all), and configure subdomain DNS records.

## Features

*   **Add Sites & Setup Email**: Automatically adds a new site to your Cloudflare account, enables Email Routing, and creates a "Catch-All" rule forwarding to your specified email.
*   **Subdomain Routing**: Quickly adds MX and SPF records to a specific subdomain for multiple domains at once.
*   **List Emails**: Fetches and lists available destination email addresses from your Cloudflare account.
*   **Configuration**: Saves your API Token and Email locally in `config.json` for convenience.
*   **Threaded Operations**: Runs long tasks in the background so the interface doesn't freeze.

## Prerequisites

*   Python 3.x
*   A Cloudflare Account
*   Cloudflare API Token (with permissions for Zone:Edit, Account:Read, Email Routing:Edit)

## Installation

1.  Clone or download this repository.
2.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Running form Source

Run the main script:
```bash
python main.py
```

### Building the Executable

Double-click `build_project.bat` to automatically build a standalone `.exe` file. The output file `CloudflareManager.exe` will be created in the main folder.

## Configuration

The application will ask for:
*   **Cloudflare API Token**: Your unique API token.
*   **Cloudflare Email**: The email address associated with your account.
*   **Forwarding Email**: The destination address for catch-all routing.

These details are saved to `config.json` automatically after the first use.

## Notes

*   **Global API Key vs API Token**: The app supports both. It automatically detects if you are using a Global API Key (37 hex characters) or a scoped API Token.
