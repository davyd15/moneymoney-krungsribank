# MoneyMoney Extension – Krungsri Bank

A [MoneyMoney](https://moneymoney-app.com) extension for **Krungsri Bank (BAY) Thailand** via the [Krungsri Biz Online](https://www.krungsribizonline.com) web portal. Fetches account balances and transactions for business accounts.

---

## Features

- Supports **Savings (SA), Current (CA), and Fixed Deposit (FD)** accounts in THB
- Fetches up to **180 days** of transaction history
- **No 2FA / SMS OTP required** — authenticates directly via session token
- Pure-Lua AES-ECB implementation for portal authentication (no external dependencies)
- Handles ASPX ViewState and AJAX-based transaction loading automatically

## How It Works

The extension implements MoneyMoney's `WebBanking` Lua API and communicates with the Krungsri Biz Online portal at `krungsribizonline.com`.

### Authentication

The portal uses ASP.NET Web Forms with AES-ECB-PKCS7 password encryption. Login is a two-step process:

1. `GET` the login page → extract ASP.NET `__ViewState`, `__EventValidation`, and the AES encryption key embedded in the page
2. Encrypt the password using AES-ECB-PKCS7 (Base64-encoded), then `POST` the encrypted credentials together with the form tokens → receive a session cookie

The AES-ECB encryption is implemented entirely in Lua with no external dependencies — including the S-Box lookup table, key expansion, `GF(2⁸)` multiplication (`gmul`), and PKCS7 padding.

### Data Retrieval

The portal loads transaction data via ASP.NET AJAX `UpdatePanel` (`__ASYNCPOST`). The extension reverse-engineers the `__doPostBack` calls the browser would normally make to navigate the account list and fetch transaction pages:

- **Accounts:** parsed from the initial post-login page HTML
- **Transactions:** fetched via ASYNCPOST with `__VIEWSTATE`/`__EventValidation` tokens refreshed from each response

## Requirements

- [MoneyMoney](https://moneymoney-app.com) for macOS (any recent version)
- A **Krungsri Biz Online** account at Krungsri Bank
- Your **Krungsri Biz Online username** and **password**

> **Note:** This extension is designed for Krungsri Biz Online (business banking portal). Personal K-Plus / KMA customers use a different portal and this extension will not work for them.

## Installation

### Option A — Direct download

1. Download [`KrungsriBank.lua`](KrungsriBank.lua)
2. Move it into MoneyMoney's Extensions folder:
   ```
   ~/Library/Containers/com.moneymoney-app.retail/Data/Library/Application Support/MoneyMoney/Extensions/
   ```
3. In MoneyMoney, go to **Help → Show Database in Finder** if you need to locate the folder.
4. Reload extensions in MoneyMoney: right-click any account → **Reload Extensions** (or restart the app).

### Option B — Clone the repository

```bash
git clone https://github.com/davyd15/moneymoney-krungsribank.git
cp moneymoney-krungsribank/KrungsriBank.lua \
  ~/Library/Containers/com.moneymoney-app.retail/Data/Library/Application\ Support/MoneyMoney/Extensions/
```

## Setup in MoneyMoney

1. Open MoneyMoney and add a new account: **File → Add Account…**
2. Search for **"Krungsri"** or **"BAY"**
3. Select **Krungsri Bank (Biz Online)**
4. Enter your **Krungsri Biz Online username** and **password**
5. Click **Next** — MoneyMoney will connect and import your accounts

## Supported Account Types

| Type | Description |
|------|-------------|
| Savings (SA) | Standard savings accounts |
| Current (CA) | Current / cheque accounts |
| Fixed Deposit (FD) | Fixed term deposit accounts |

## Limitations

- **THB only** — foreign currency accounts are not supported
- **Max 180 days** history per refresh (portal limitation)
- Business portal only — not compatible with personal K-Plus / KMA accounts

## Troubleshooting

**"Login failed" / credentials rejected**
- Make sure you are using your **Krungsri Biz Online credentials**, not K-Plus or KMA credentials
- Try logging in at [https://www.krungsribizonline.com](https://www.krungsribizonline.com) in your browser to verify your credentials

**Extension not appearing in MoneyMoney**
- Confirm the `.lua` file is in the correct Extensions folder (see Installation above)
- Reload extensions or restart MoneyMoney

**Transactions missing / history too short**
- The portal limits history to 180 days. Older transactions cannot be retrieved.

## Changelog

| Version | Changes |
|---------|---------|
| 1.09 | Fix HTML entity decoding for form action URLs (`&amp;` → `&` in ASYNCPOST) |
| 1.00 | Initial public release |

## Contributing

Bug reports and pull requests are welcome. If the bank changes its login flow or API, please open an issue with the MoneyMoney log output — that makes it much easier to diagnose.

To test changes locally, copy the `.lua` file into the Extensions folder and reload extensions in MoneyMoney.

## Disclaimer

This extension is an independent community project and is **not affiliated with, endorsed by, or supported by Krungsri Bank** or the MoneyMoney developers. Use at your own risk. Credentials are handled solely by MoneyMoney's built-in secure storage and are never transmitted to any third party.

## License

MIT — see [LICENSE](LICENSE)
