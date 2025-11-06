import os
import time
import requests
import logging
from requests.auth import HTTPBasicAuth
from prometheus_client import start_http_server, Gauge, Counter, Info

# --- Configuration from Environment Variables ---
WAZUH_API_URL = os.environ.get("WAZUH_API_URL")
WAZUH_USER = os.environ.get("WAZUH_USER")
WAZUH_PASS = os.environ.get("WAZUH_PASS")
PORT = int(os.environ.get("PORT", 9115))
SCRAPE_INTERVAL = int(os.environ.get("SCRAPE_INTERVAL", 30))

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# --- Disable self-signed certificate warnings ---
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

# --- Prometheus Metrics Definitions ---
wazuh_info = Info("wazuh", "Wazuh manager and API version information")
wazuh_api_up = Gauge("wazuh_api_up", "Wazuh API health status (1=up, 0=down)")
wazuh_manager_up = Gauge(
    "wazuh_manager_up", "Wazuh manager service status (1=up, 0=down)"
)

wazuh_agents_total = Gauge(
    "wazuh_agents_total", "Total number of Wazuh agents by status", ["status"]
)
wazuh_agent_status = Gauge(
    "wazuh_agent_status",
    "Wazuh agent connection status (1=active, 0=other)",
    ["agent_id", "agent_name"],
)

wazuh_api_scrape_errors_total = Counter(
    "wazuh_api_scrape_errors_total",
    "Total number of errors encountered scraping the Wazuh API",
)

# --- Global variable for API token ---
wazuh_api_token = None


def get_wazuh_token():
    """
    Authenticates with the Wazuh API and retrieves a JWT token.
    Returns the token string or None if authentication fails.
    """
    global wazuh_api_token
    try:
        url = f"{WAZUH_API_URL}/security/user/authenticate"
        response = requests.post(
            url, auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASS), verify=False
        )

        if response.status_code == 200:
            wazuh_api_token = response.json()["data"]["token"]
            logging.info("Successfully authenticated with Wazuh API.")
            wazuh_api_up.set(1)
            return wazuh_api_token
        else:
            logging.error(
                f"Failed to authenticate with Wazuh API. Status: {response.status_code}, Response: {response.text}"
            )
            wazuh_api_up.set(0)
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during authentication: {e}")
        wazuh_api_up.set(0)
        return None


def api_request(endpoint, params=None):
    """
    Makes an authenticated GET request to a Wazuh API endpoint.
    Handles token refresh on 401.
    """
    if wazuh_api_token is None:
        if not get_wazuh_token():
            raise Exception("Authentication failed, cannot make API request.")

    headers = {"Authorization": f"Bearer {wazuh_api_token}"}
    url = f"{WAZUH_API_URL}{endpoint}"

    try:
        response = requests.get(url, headers=headers, params=params, verify=False)

        if response.status_code == 401:
            logging.warning("API token expired or invalid. Re-authenticating...")
            if not get_wazuh_token():
                raise Exception("Re-authentication failed.")
            # Retry with new token
            headers = {"Authorization": f"Bearer {wazuh_api_token}"}
            response = requests.get(url, headers=headers, params=params, verify=False)

        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()

    except requests.exceptions.RequestException as e:
        logging.error(f"API request to {endpoint} failed: {e}")
        wazuh_api_scrape_errors_total.inc()
        return None  # Return None to signal failure


def collect_metrics():
    """
    Scrapes all metrics from the Wazuh API.
    """
    try:
        # --- Get basic API info (and test auth) ---
        info_data = api_request("/")
        if not info_data:
            wazuh_api_up.set(0)
            logging.error("API is down or auth failed. Skipping scrape cycle.")
            return  # Exit if we can't even get basic info

        wazuh_api_up.set(1)
        wazuh_info.info(
            {
                "api_version": info_data["data"]["api_version"],
                "manager_version": info_data["data"].get(
                    "title", "unknown"
                ),  # Title often has manager version
            }
        )

        # --- 1. Manager Status ---
        manager_status_data = api_request("/manager/status")
        if manager_status_data:
            daemons = manager_status_data["data"]
            all_running = all(d == "running" for d in daemons.values())
            wazuh_manager_up.set(1 if all_running else 0)
        else:
            wazuh_manager_up.set(0)

        # --- 2. Agent Summary (Total Agents) ---
        agent_summary_data = api_request("/agents/summary/status")
        wazuh_agents_total.clear()
        if agent_summary_data:
            for status, count in agent_summary_data["data"]["connection"].items():
                wazuh_agents_total.labels(status=status).set(count)

        # --- 3. Per-Agent Status ---
        # Wazuh API max limit is 100,000
        agent_list_data = api_request(
            "/agents", params={"limit": 100000, "select": "id,name,status"}
        )
        wazuh_agent_status.clear()
        if agent_list_data:
            for agent in agent_list_data["data"]["affected_items"]:
                status_val = 1 if agent["status"] == "active" else 0
                wazuh_agent_status.labels(
                    agent_id=agent["id"], agent_name=agent["name"]
                ).set(status_val)

        logging.info("Successfully scraped all metrics.")

    except Exception as e:
        logging.error(f"An error occurred during the scrape cycle: {e}")
        wazuh_api_scrape_errors_total.inc()


def main():
    """
    Starts the Prometheus exporter server and runs the scrape loop.
    """
    if not all([WAZUH_API_URL, WAZUH_USER, WAZUH_PASS]):
        logging.error(
            "Missing environment variables: WAZUH_API_URL, WAZUH_USER, or WAZUH_PASS. Exiting."
        )
        return

    logging.info(f"Starting Wazuh Prometheus Exporter on port {PORT}")
    start_http_server(PORT)

    # Run initial scrape
    get_wazuh_token()
    collect_metrics()

    while True:
        time.sleep(SCRAPE_INTERVAL)
        collect_metrics()


if __name__ == "__main__":
    main()
