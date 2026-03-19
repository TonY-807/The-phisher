import requests

urls = [
    'https://www.google.com',
    'http://wikipedia.org',
    'http://192.168.1.1/login_verify.html'
]

for url in urls:
    print(f"Testing {url}...")
    try:
        response = requests.post('http://127.0.0.1:5000/', data={'url': url})
        # Extract classification from HTML
        if 'Safe Risk' in response.text:
            print("Result: Safe")
        elif 'Suspicious Risk' in response.text:
            print("Result: Suspicious")
        elif 'Phishing Risk' in response.text:
            print("Result: Phishing")
        else:
            print("Result: Unknown (could not parse)")
    except Exception as e:
        print(f"Error: {e}")
    print("-" * 20)
