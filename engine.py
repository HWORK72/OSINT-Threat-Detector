import asyncio
import logging
import os
import re
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

class OSINTScanner:
    def __init__(self) -> None:
        self.ip_api_url = "http://ip-api.com/json/"
        self.shodan_idb_url = "https://internetdb.shodan.io/"
        self.hibp_url = "https://haveibeenpwned.com/api/v3/breachedaccount/"
        self.otx_url = "https://otx.alienvault.com/api/v1/indicators/"
        self.hibp_key = os.getenv("HIBP_API_KEY", "")
        self.otx_key = os.getenv("OTX_API_KEY", "")

    def _classify_target(self, target: str) -> str:
        ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        email_pattern = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

        if ip_pattern.match(target):
            return "IPv4"
        if email_pattern.match(target):
            return "email"
        return "domain"

    async def fetch_ip_info(self, session: aiohttp.ClientSession, target: str) -> dict[str, Any]:
        try:
            async with session.get(f"{self.ip_api_url}{target}", timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "success":
                        return {"source": "IP-API", "data": data, "error": None}
        except asyncio.TimeoutError:
            logger.warning(f"Timeout connecting to IP-API for target: {target}")
        except Exception:
            logger.error(f"IP-API request failed for target: {target}", exc_info=True)
        return {"source": "IP-API", "data": None, "error": "Request failed"}

    async def fetch_shodan_info(self, session: aiohttp.ClientSession, target: str) -> dict[str, Any]:
        try:
            async with session.get(f"{self.shodan_idb_url}{target}", timeout=5) as response:
                if response.status == 200:
                    return {"source": "Shodan IDB", "data": await response.json(), "error": None}
                if response.status == 404:
                    return {"source": "Shodan IDB", "data": None, "error": "Not found in DB"}
        except asyncio.TimeoutError:
            logger.warning(f"Timeout connecting to Shodan for target: {target}")
        except Exception:
            logger.error(f"Shodan request failed for target: {target}", exc_info=True)
        return {"source": "Shodan IDB", "data": None, "error": "Request failed"}

    async def fetch_hibp_leaks(self, session: aiohttp.ClientSession, target: str) -> dict[str, Any]:
        if not self.hibp_key:
            return {"source": "HaveIBeenPwned", "data": None, "error": "Missing API Key in .env"}

        headers = {
            "hibp-api-key": self.hibp_key,
            "user-agent": "OSINT-Analyzer-App"
        }
        try:
            async with session.get(f"{self.hibp_url}{target}?truncateResponse=false", headers=headers, timeout=5) as response:
                if response.status == 200:
                    return {"source": "HaveIBeenPwned", "data": await response.json(), "error": None}
                if response.status == 404:
                    return {"source": "HaveIBeenPwned", "data": [], "error": "No leaks found"}
                if response.status == 401:
                    return {"source": "HaveIBeenPwned", "data": None, "error": "Invalid API Key"}
        except asyncio.TimeoutError:
            logger.warning(f"Timeout connecting to HIBP for target: {target}")
        except Exception:
            logger.error(f"HIBP request failed for target: {target}", exc_info=True)
        return {"source": "HaveIBeenPwned", "data": None, "error": "Request failed"}

    async def fetch_otx_threats(self, session: aiohttp.ClientSession, target: str, target_type: str) -> dict[str, Any]:
        if not self.otx_key:
            return {"source": "AlienVault OTX", "data": None, "error": "Missing API Key in .env"}

        headers = {"X-OTX-API-KEY": self.otx_key}
        try:
            async with session.get(f"{self.otx_url}{target_type}/{target}/general", headers=headers, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    return {"source": "AlienVault OTX", "data": {"pulses_found": pulse_count}, "error": None}
                if response.status == 401:
                    return {"source": "AlienVault OTX", "data": None, "error": "Invalid API Key"}
        except asyncio.TimeoutError:
            logger.warning(f"Timeout connecting to OTX for target: {target}")
        except Exception:
            logger.error(f"OTX request failed for target: {target}", exc_info=True)
        return {"source": "AlienVault OTX", "data": None, "error": "Request failed"}

    async def analyze(self, session: aiohttp.ClientSession, target: str) -> dict[str, Any]:
        target_type = self._classify_target(target)
        tasks = []

        if target_type == "email":
            tasks.append(self.fetch_hibp_leaks(session, target))
        else:
            tasks.append(self.fetch_ip_info(session, target))
            tasks.append(self.fetch_shodan_info(session, target))
            tasks.append(self.fetch_otx_threats(session, target, target_type))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # --- НАЧАЛО НОВОГО БЛОКА ПОДСЧЕТА ---
        real_threat_score = 0

        for res in results:
            # Проверяем, что результат успешный и это словарь (а не ошибка от asyncio)
            if isinstance(res, dict) and res.get("error") is None and res.get("data"):
                source = res["source"]

                if source == "AlienVault OTX":
                    pulses = res["data"].get("pulses_found", 0)
                    real_threat_score += pulses * 10

                elif source == "HaveIBeenPwned":
                    breaches = len(res["data"])
                    real_threat_score += breaches * 20

                elif source == "Shodan IDB":
                    ports = res["data"].get("ports") or []
                    dangerous_ports = {22, 23, 3389, 445}  # SSH, Telnet, RDP, SMB
                    if set(ports).intersection(dangerous_ports):
                        real_threat_score += 50

        return {
            "target": target,
            "type": target_type,
            "threat_score": real_threat_score,
            "sources_checked": len(tasks),
            "results": [res if isinstance(res, dict) else {"error": str(res)} for res in results]
        }