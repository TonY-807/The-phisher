import requests

try:
    response = requests.post('http://127.0.0.1:5000/download_report', data={'url': 'https://www.google.com'})
    if response.status_code == 200 and 'pdf' in response.headers.get('Content-Type', '').lower():
        print("Success! PDF downloaded.")
        with open("test_report.pdf", "wb") as f:
            f.write(response.content)
    else:
        print(f"Failed. Status: {response.status_code}")
except Exception as e:
    print(f"Error: {e}")
