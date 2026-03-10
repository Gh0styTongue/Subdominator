import httpx
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from subdominator.modules.logger.logger import logger

async def check_sourcemap_leakage(subdomain, timeout=10):
    """
    Scans a subdomain for .js.map leakage. 
    Flags as vulnerable if > 3 maps are found.
    """
    found_maps = []
    url = f"http://{subdomain}"
    
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return None

            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = [script['src'] for script in soup.find_all('script', src=True)]
            
            for js_url in scripts:
                full_js_url = urljoin(url, js_url)
                map_url = f"{full_js_url}.map"
                
                try:
                    map_res = await client.get(map_url)
                    if map_res.status_code == 200 and "application/json" in map_res.headers.get("Content-Type", ""):
                        found_maps.append(map_url)
                except httpx.RequestError:
                    continue

            if len(found_maps) > 3:
                return {
                    "subdomain": subdomain,
                    "vulnerable": True,
                    "count": len(found_maps),
                    "files": found_maps
                }
    except Exception as e:
        pass
        
    return None
