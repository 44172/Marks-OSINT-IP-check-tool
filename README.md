Handy lookup tool to check IPs or Domains against open source information sites like virtus total, greynoise, OTX, TAXII, STIX, Alien vault, Shodan.

Install Python and pip install dependencies -> 
        Flask, requests, ollama, whois, 
        shodan, dotenv, os, taxii2client.v20, 
        stix2, socket, re
        
Install ollama with model qwen3:8b running locally ( can use other models by changing line 435 respectively)

Fill out your API keys in the .env.example file and rename to .env

Run app.py

browse to http://localhost:5000 and enter your seach query
