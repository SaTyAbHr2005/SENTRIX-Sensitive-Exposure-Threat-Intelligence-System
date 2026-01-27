import time
import requests
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem

software_names = [
    SoftwareName.CHROME.value,
    SoftwareName.FIREFOX.value,
    SoftwareName.EDGE.value
]
operating_systems = [
    OperatingSystem.WINDOWS.value,
    OperatingSystem.LINUX.value,
    OperatingSystem.MAC.value
]

ua_rotator = UserAgent(
    software_names=software_names,
    operating_systems=operating_systems
)

def get_random_ua():
    return ua_rotator.get_random_user_agent()

# Disable SSL warnings (optional)
requests.packages.urllib3.disable_warnings()

REQUEST_TIMEOUT = 10       # per-connection timeout
HARD_TIMEOUT = 12          # absolute stop time

def safe_get(url):
    """
    EXACT logic from your crawler:
    - Random UA
    - socket timeout
    - hard timeout via chunk iteration
    - returns {ok, response, error}
    """

    start = time.time()

    try:
        headers = {"User-Agent": get_random_ua()}

        resp = requests.get(
            url,
            timeout=(REQUEST_TIMEOUT, REQUEST_TIMEOUT),
            headers=headers,
            verify=False,
            stream=True
        )

        content = []
        for chunk in resp.iter_content(chunk_size=1024):
            content.append(chunk)

            # Hard timeout
            if time.time() - start > HARD_TIMEOUT:
                return {
                    "ok": False,
                    "response": None,
                    "error": f"Hard timeout reached while requesting {url}"
                }

        resp._content = b"".join(content)
        return {"ok": True, "response": resp, "error": None}

    except requests.exceptions.Timeout:
        return {
            "ok": False,
            "response": None,
            "error": f"Socket timeout while requesting {url}"
        }

    except Exception as e:
        return {
            "ok": False,
            "response": None,
            "error": f"Request failed for {url}: {str(e)}"
        }
