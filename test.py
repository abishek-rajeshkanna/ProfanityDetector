import requests

url = "http://localhost:5000/profanity-detect"
headers = {"api-key": "82c5a3e80ffc2cb6d0edea93436c4581"}

# Open the file in binary mode
with open(r"C:\Users\purus\Downloads\test1.png", "rb") as f:
    files = {"file": ("test1.png", f, "image/png")}  # Ensure correct format

    response = requests.post(url, headers=headers, files=files)

print(response.json())
