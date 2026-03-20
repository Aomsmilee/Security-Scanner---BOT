<img width="1125" height="47" alt="ภาพถ่ายหน้าจอ 2569-03-20 เวลา 14 54 57" src="https://github.com/user-attachments/assets/31d11dd6-0225-4b50-b8e9-da450170cac4" /># Security Scanner Bot
This is a bot developed in Python for the LINE and Discord platforms. It scans for files and links sent in chat channels, connecting to the VirusTotal API to check against its threat database.

## Features

- **URL Scanning**: Checks links for phishing and malicious content before users click them.  
- **File Hash Analysis**: Scans uploaded files or user-provided SHA-256 hashes against the VirusTotal database.   
- **Real-time Responses**: Fast asynchronous processing.  
- **Multi-Platform Support**: Works on both Discord and LINE messaging platforms.  

## Supported Platforms

- Discord Bot  
- LINE Bot  

## Limitations in Discord.
If any file is malicious, Discord will immediately block the upload, making it impossible to test the bot.

## Disadvantages in line
If any files are large, it may take a little longer to scan.
